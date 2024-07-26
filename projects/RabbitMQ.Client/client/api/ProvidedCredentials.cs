using System;

namespace RabbitMQ.Client
{
    public class ProvidedCredentials : IProvidedCredentials
    {
        public string UserName { get; }
        public string Password { get; }
        public TimeSpan? ValidUntil { get; }

        public ProvidedCredentials(string userName, string password, TimeSpan? validUntil)
        {
            UserName = userName;
            Password = password;
            ValidUntil = validUntil;
        }
    }
}
