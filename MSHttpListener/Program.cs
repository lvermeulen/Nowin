namespace MSHttpListener
{
    using System;
    using Microsoft.Owin;
    using Microsoft.Owin.Hosting;
    using Owin;

    internal class Program
    {
        private static void Main(string[] args)
        {
            Action<IAppBuilder> startup = app =>
            {
                app.Run(async ctx =>
                {
                    await ctx.Response.WriteAsync("Hello MSHttpListener");
                });
            };
            using(WebApp.Start("https://*:8887", startup))
            using(WebApp.Start("http://*:9999", startup))
            {
                Console.WriteLine("Server running...");
                Console.ReadLine();
            }
        }
    }
}