﻿using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Nowin;

// Heavily inspired by Katana project OwinHttpListener tests

namespace NowinTests
{
    public class NowinTestsSecure : NowinTestsBase
    {
        readonly X509Certificate _certificate;

        public NowinTestsSecure()
        {
            _certificate = new X509Certificate2("test.pfx", "nowin");
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
        }

        protected override string HttpClientAddress
        {
            get { return "https://localhost:8082/"; }
        }

        protected override string ExpectedRequestScheme
        {
            get { return "https"; }
        }

        protected override IDisposable CreateServer(Func<IDictionary<string, object>, Task> app)
        {
            var server = ServerBuilder.New()
                .SetEndPoint(new IPEndPoint(IPAddress.Loopback, 8082))
                .SetCertificate(_certificate)
                .SetOwinApp(app)
                .SetConnectionAllocationStrategy(new ConnectionAllocationStrategy(1, 0, 1, 0))
                .SetRetrySocketBindingTime(TimeSpan.FromSeconds(4))
                .Start();
            return server;
        }
    }
}
