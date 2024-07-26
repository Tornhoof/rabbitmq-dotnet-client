// This source code is dual-licensed under the Apache License, version
// 2.0, and the Mozilla Public License, version 2.0.
//
// The APL v2.0:
//
//---------------------------------------------------------------------------
//   Copyright (c) 2007-2024 Broadcom. All Rights Reserved.
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       https://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//---------------------------------------------------------------------------
//
// The MPL v2.0:
//
//---------------------------------------------------------------------------
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
//  Copyright (c) 2007-2024 Broadcom. All Rights Reserved.
//---------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace RabbitMQ.Client.OAuth2
{
    public interface IOAuth2Client
    {
        Task<IToken> RequestTokenAsync(CancellationToken cancellationToken = default);
        Task<IToken> RefreshTokenAsync(IToken token, CancellationToken cancellationToken = default);
    }

    public interface IToken
    {
        string AccessToken { get; }
        string RefreshToken { get; }
        TimeSpan ExpiresIn { get; }
        bool HasExpired { get; }
    }

    public class Token : IToken
    {
        private readonly JsonToken _source;
        private readonly DateTime _lastTokenRenewal;

        public Token(JsonToken json)
        {
            _source = json;
            _lastTokenRenewal = DateTime.Now;
        }

        public string AccessToken
        {
            get
            {
                return _source.AccessToken;
            }
        }

        public string RefreshToken
        {
            get
            {
                return _source.RefreshToken;
            }
        }

        public TimeSpan ExpiresIn
        {
            get
            {
                return TimeSpan.FromSeconds(_source.ExpiresIn);
            }
        }

        bool IToken.HasExpired
        {
            get
            {
                TimeSpan age = DateTime.Now - _lastTokenRenewal;
                return age > ExpiresIn;
            }
        }
    }

    public class OAuth2ClientBuilder
    {
        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly Uri _tokenEndpoint;
        private string _scope;
        private IDictionary<string, string> _additionalRequestParameters;
        private HttpClientHandler _httpClientHandler;

        public OAuth2ClientBuilder(string clientId, string clientSecret, Uri tokenEndpoint)
        {
            _clientId = clientId ?? throw new ArgumentNullException(nameof(clientId));
            _clientSecret = clientSecret ?? throw new ArgumentNullException(nameof(clientSecret));
            _tokenEndpoint = tokenEndpoint ?? throw new ArgumentNullException(nameof(tokenEndpoint));

        }

        public OAuth2ClientBuilder SetScope(string scope)
        {
            _scope = scope ?? throw new ArgumentNullException(nameof(scope));
            return this;
        }

        public OAuth2ClientBuilder SetHttpClientHandler(HttpClientHandler handler)
        {
            _httpClientHandler = handler ?? throw new ArgumentNullException(nameof(handler));
            return this;
        }

        public OAuth2ClientBuilder AddRequestParameter(string param, string paramValue)
        {
            if (param == null)
            {
                throw new ArgumentNullException("param is null");
            }
            if (paramValue == null)
            {
                throw new ArgumentNullException("paramValue is null");
            }
            if (_additionalRequestParameters == null)
            {
                _additionalRequestParameters = new Dictionary<string, string>();
            }
            _additionalRequestParameters[param] = paramValue;
            return this;
        }

        public IOAuth2Client Build()
        {
            return new OAuth2Client(_clientId, _clientSecret, _tokenEndpoint,
                _scope, _additionalRequestParameters, _httpClientHandler);
        }
    }

    /**
    * Default implementation of IOAuth2Client. It uses Client_Credentials OAuth2 flow to request a
    * token. The basic constructor assumes no scopes are needed only the OAuth2 Client credentiuals.
    * The additional constructor accepts a Dictionary with all the request parameters passed onto the
    * OAuth2 request token.
    */
    internal class OAuth2Client : IOAuth2Client, IDisposable
    {
        private const string GrantType = "grant_type";
        private const string ClientId = "client_id";
        private const string Scope = "scope";
        private const string ClientSecret = "client_secret";
        private const string REFRESH_TOKEN = "refresh_token";
        private const string GrantTypeClientCredentials = "client_credentials";

        private readonly string _clientId;
        private readonly string _clientSecret;
        private readonly Uri _tokenEndpoint;
        private readonly string _scope;
        private readonly IDictionary<string, string> _additionalRequestParameters;

        private static readonly IDictionary<string, string> Empty = new Dictionary<string, string>();

        private readonly HttpClient _httpClient;

        public OAuth2Client(string clientId, string clientSecret, Uri tokenEndpoint, string scope,
                IDictionary<string, string> additionalRequestParameters,
                HttpClientHandler httpClientHandler)
        {
            _clientId = clientId;
            _clientSecret = clientSecret;
            _scope = scope;
            _additionalRequestParameters = additionalRequestParameters == null ? Empty : additionalRequestParameters;
            _tokenEndpoint = tokenEndpoint;

            _httpClient = httpClientHandler == null ? new HttpClient() :
                new HttpClient(httpClientHandler);
            _httpClient.DefaultRequestHeaders.Accept.Clear();
            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        }

        public async Task<IToken> RequestTokenAsync(CancellationToken cancellationToken = default)
        {
            using (var req = new HttpRequestMessage(HttpMethod.Post, _tokenEndpoint))
            {
                req.Content = new FormUrlEncodedContent(BuildRequestParameters());

                using (var response = await _httpClient.SendAsync(req, cancellationToken).ConfigureAwait(false))
                {
                    response.EnsureSuccessStatusCode();
                    var token = await response.Content
                        .ReadFromJsonAsync<JsonToken>(cancellationToken: cancellationToken)
                        .ConfigureAwait(false);
                    return new Token(token);
                }
            }
        }

        public async Task<IToken> RefreshTokenAsync(IToken token, CancellationToken cancellationToken = default)
        {
            if (token.RefreshToken == null)
            {
                throw new InvalidOperationException("Token has no Refresh Token");
            }

            using (var req = new HttpRequestMessage(HttpMethod.Post, _tokenEndpoint))
            {
                req.Content = new FormUrlEncodedContent(BuildRefreshParameters(token));

                using (var response = await _httpClient.SendAsync(req, cancellationToken).ConfigureAwait(false))
                {
                    response.EnsureSuccessStatusCode();
                    var refreshedToken = await response.Content
                        .ReadFromJsonAsync<JsonToken>(cancellationToken: cancellationToken)
                        .ConfigureAwait(false);
                    return new Token(refreshedToken);
                }
            }
        }

        public void Dispose()
        {
            _httpClient.Dispose();
        }

        private Dictionary<string, string> BuildRequestParameters()
        {
            var dict = new Dictionary<string, string>(_additionalRequestParameters)
            {
                { ClientId, _clientId },
                { ClientSecret, _clientSecret }
            };
            if (_scope != null && _scope.Length > 0)
            {
                dict.Add(Scope, _scope);
            }
            dict.Add(GrantType, GrantTypeClientCredentials);
            return dict;
        }

        private Dictionary<string, string> BuildRefreshParameters(IToken token)
        {
            var dict = BuildRequestParameters();
            dict.Remove(GrantType);
            dict.Add(GrantType, REFRESH_TOKEN);
            if (_scope != null)
            {
                dict.Add(Scope, _scope);
            }
            dict.Add(REFRESH_TOKEN, token.RefreshToken);
            return dict;
        }
    }

    public class JsonToken
    {
        public JsonToken()
        {
        }

        public JsonToken(string accessToken, string refreshToken, TimeSpan expiresInSpan)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            ExpiresIn = (long)expiresInSpan.TotalSeconds;
        }

        public JsonToken(string accessToken, string refreshToken, long expiresIn)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;
            ExpiresIn = expiresIn;
        }

        [JsonPropertyName("access_token")]
        public string AccessToken
        {
            get; set;
        }

        [JsonPropertyName("refresh_token")]
        public string RefreshToken
        {
            get; set;
        }

        [JsonPropertyName("expires_in")]
        public long ExpiresIn
        {
            get; set;
        }
    }
}
