using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Security;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace Nowin
{
    class SslTransportHandler : ITransportLayerHandler, ITransportLayerCallback
    {
        readonly ITransportLayerHandler _next;
        readonly X509Certificate _serverCertificate;
        SslStream _ssl;
        Task _authenticateTask;
        byte[] _recvBuffer;
        int _recvOffset;
        int _recvLength;
        readonly InputStream _inputStream;
        IPEndPoint _remoteEndPoint;
        IPEndPoint _localEndPoint;

        public SslTransportHandler(ITransportLayerHandler next, X509Certificate serverCertificate)
        {
            _next = next;
            _serverCertificate = serverCertificate;
            _inputStream = new InputStream(this);
            next.Callback = this;
        }

        class InputStream : Stream
        {
            readonly SslTransportHandler _owner;
            TaskCompletionSource<int> _tcsReceive;
            AsyncCallback _callbackReceive;
            TaskCompletionSource<object> _tcsSend;
            AsyncCallback _callbackSend;

            public InputStream(SslTransportHandler owner)
            {
                _owner = owner;
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new InvalidOperationException();
            }

            public override void SetLength(long value)
            {
                throw new InvalidOperationException();
            }

            public void FinishReceive(int length)
            {
                if (length == -1)
                    _tcsReceive.SetCanceled();
                else
                    _tcsReceive.SetResult(length);
                if (_callbackReceive != null)
                {
                    _callbackReceive(_tcsReceive.Task);
                }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                return ReadOverflowAsync(buffer, offset, count, null, null).Result;
            }

            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                return ReadOverflowAsync(buffer, offset, count, null, null);
            }

            Task<int> ReadOverflowAsync(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
            {
                _tcsReceive = new TaskCompletionSource<int>(state);
                _callbackReceive = callback;
                _owner.Callback.StartReceive(buffer, offset, count);
                return _tcsReceive.Task;
            }

            public void FinishSend(Exception exception)
            {
                if (exception == null)
                {
                    _tcsSend.SetResult(null);
                }
                else
                {
                    _tcsSend.SetException(exception);
                }
                if (_callbackSend != null)
                {
                    _callbackSend(_tcsSend.Task);
                }
            }

            public override void Flush()
            {
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                WriteAsync(buffer, offset, count, CancellationToken.None).Wait();
            }

            public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                _tcsSend = new TaskCompletionSource<object>();
                _owner.Callback.StartSend(buffer, offset, count);
                return _tcsSend.Task;
            }

            public override bool CanRead
            {
                get { return true; }
            }

            public override bool CanSeek
            {
                get { return false; }
            }

            public override bool CanWrite
            {
                get { return true; }
            }

            public override long Length
            {
                get { return long.MaxValue; }
            }

            public override long Position { get; set; }
        }

        public void Dispose()
        {
            _next.Dispose();
        }

        public ITransportLayerCallback Callback { set; private get; }

        public void PrepareAccept()
        {
            _ssl = null;
            _next.PrepareAccept();
        }

        public void FinishAccept(byte[] buffer, int offset, int length, IPEndPoint remoteEndPoint, IPEndPoint localEndPoint)
        {
            _remoteEndPoint = remoteEndPoint;
            _localEndPoint = localEndPoint;
            Debug.Assert(length == 0);
            try
            {
                _ssl = new SslStream(_inputStream, true);
                _authenticateTask = _ssl.AuthenticateAsServerAsync(_serverCertificate).ContinueWith((t, selfObject) =>
                {
                    var self = (SslTransportHandler)selfObject;
                    if (t.IsFaulted || t.IsCanceled)
                        self._next.FinishAccept(null, 0, 0, null, null);
                    else
                        self._ssl.ReadAsync(self._recvBuffer, self._recvOffset, self._recvLength).ContinueWith((t2, selfObject2) =>
                        {
                            var self2 = (SslTransportHandler)selfObject2;
                            if (t2.IsFaulted || t2.IsCanceled)
                                self2._next.FinishAccept(null, 0, 0, null, null);
                            else
                                self2._next.FinishAccept(self2._recvBuffer, self2._recvOffset, t2.Result, self2._remoteEndPoint, self2._localEndPoint);
                        }, self);
                }, this);
            }
            catch (Exception)
            {
                Callback.StartDisconnect();
            }
        }

        public void FinishReceive(byte[] buffer, int offset, int length)
        {
            _inputStream.FinishReceive(length);
        }

        public void FinishSend(Exception exception)
        {
            _inputStream.FinishSend(exception);
        }

        public void StartAccept(byte[] buffer, int offset, int length)
        {
            _recvBuffer = buffer;
            _recvOffset = offset;
            _recvLength = length;
            Callback.StartAccept(null, 0, 0);
        }

        public void StartReceive(byte[] buffer, int offset, int length)
        {
            _recvBuffer = buffer;
            _recvOffset = offset;
            _recvLength = length;
            try
            {
                _ssl.ReadAsync(buffer, offset, length).ContinueWith((t, selfObject) =>
                {
                    var self = (SslTransportHandler)selfObject;
                    if (t.IsFaulted || t.IsCanceled || t.Result == 0)
                        self._next.FinishReceive(null, 0, -1);
                    else
                        self._next.FinishReceive(self._recvBuffer, self._recvOffset, t.Result);
                }, this);
            }
            catch (Exception)
            {
                _next.FinishReceive(null, 0, -1);
            }
        }

        public void StartSend(byte[] buffer, int offset, int length)
        {
            try
            {
                _ssl.WriteAsync(buffer, offset, length).ContinueWith((t, selfObject) =>
                {
                    var self = (SslTransportHandler)selfObject;
                    if (t.IsCanceled)
                    {
                        self._next.FinishSend(new OperationCanceledException());
                    }
                    else if (t.IsFaulted)
                    {
                        self._next.FinishSend(t.Exception);
                    }
                    else
                    {
                        self._next.FinishSend(null);
                    }
                }, this);
            }
            catch (Exception ex)
            {
                _next.FinishSend(ex);
            }
        }

        public void StartDisconnect()
        {
            var t = _authenticateTask;
            _authenticateTask = null;
            if (t != null)
            {
                t.ContinueWith((t2, callback) => ((ITransportLayerCallback)callback).StartDisconnect(), Callback);
            }
            else
            {
                Callback.StartDisconnect();
            }
        }
    }
}