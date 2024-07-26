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
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using RabbitMQ.Client.OAuth2;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;
using Xunit;

namespace OAuth2Test
{
    public class TestOAuth2Client
    {
        private const string ClientId = "producer";
        private const string ClientSecret = "kbOFBXI9tANgKUq8vXHLhT6YhbivgXxn";
        private readonly WireMockServer _oauthServer;

        private readonly IOAuth2Client _client;

        public TestOAuth2Client()
        {
            _oauthServer = WireMockServer.Start();

            _client = new OAuth2ClientBuilder(ClientId, ClientSecret, new System.Uri(_oauthServer.Url + "/token")).Build();
        }

        private void ExpectTokenRequest(RequestFormMatcher expectedRequestBody, JsonToken expectedResponse)
        {
            _oauthServer
                .Given(
                    Request.Create()
                        .WithPath("/token")
                        .WithBody(expectedRequestBody.Matcher())
                        .UsingPost()
                )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json;charset=UTF-8")
                    .WithBody(JsonSerializer.Serialize(expectedResponse))
                );
        }

        [Fact]
        public async Task TestRequestToken()
        {
            JsonToken expectedJsonToken = new JsonToken("the_access_token", "the_refresh_token", TimeSpan.FromSeconds(10));
            ExpectTokenRequest(new RequestFormMatcher()
                            .WithParam("client_id", ClientId)
                            .WithParam("client_secret", ClientSecret)
                            .WithParam("grant_type", "client_credentials"),
                            expectedJsonToken);

            IToken token = await _client.RequestTokenAsync();
            Assert.NotNull(token);
            Assert.Equal(expectedJsonToken.AccessToken, token.AccessToken);
            Assert.Equal(expectedJsonToken.RefreshToken, token.RefreshToken);
            Assert.Equal(TimeSpan.FromSeconds(expectedJsonToken.ExpiresIn), token.ExpiresIn);
        }

        private void ExpectTokenRefresh(JsonToken expectedResponse)
        {
            _oauthServer
                .Given(
                    Request.Create()
                        .WithPath("/token")
                        .WithParam("client_id", ClientId)
                        .WithParam("client_secret", ClientSecret)
                        .WithParam("grant_type", "refresh_token")
                        .WithParam("refresh_token", expectedResponse.RefreshToken)
                        .WithHeader("content_type", "application/x-www-form-urlencoded")
                        .UsingPost()
                )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithHeader("Content-Type", "application/json;charset=UTF-8")
                    .WithBody(JsonSerializer.Serialize(expectedResponse))
                );
        }

        [Fact]
        public async Task TestRefreshToken()
        {
            JsonToken expectedJsonToken = new JsonToken("the_access_token", "the_refresh_token", TimeSpan.FromSeconds(10));
            ExpectTokenRequest(new RequestFormMatcher()
                            .WithParam("client_id", ClientId)
                            .WithParam("client_secret", ClientSecret)
                            .WithParam("grant_type", "client_credentials"),
                            expectedJsonToken);

            IToken token = await _client.RequestTokenAsync();
            _oauthServer.Reset();

            expectedJsonToken = new JsonToken("the_access_token2", "the_refresh_token", TimeSpan.FromSeconds(20));
            ExpectTokenRequest(new RequestFormMatcher()
                            .WithParam("client_id", ClientId)
                            .WithParam("client_secret", ClientSecret)
                            .WithParam("grant_type", "refresh_token")
                            .WithParam("refresh_token", "the_refresh_token"),
                            expectedJsonToken);

            IToken refreshedToken = await _client.RefreshTokenAsync(token);
            Assert.False(refreshedToken == token);
            Assert.NotNull(refreshedToken);
            Assert.Equal(expectedJsonToken.AccessToken, refreshedToken.AccessToken);
            Assert.Equal(expectedJsonToken.RefreshToken, refreshedToken.RefreshToken);
            Assert.Equal(TimeSpan.FromSeconds(expectedJsonToken.ExpiresIn), refreshedToken.ExpiresIn);
        }

        [Fact]
        public async Task TestInvalidCredentials()
        {
            _oauthServer
                .Given(
                    Request.Create()
                        .WithPath("/token")
                        .WithBody(new RequestFormMatcher()
                            .WithParam("client_id", ClientId)
                            .WithParam("client_secret", ClientSecret)
                            .WithParam("grant_type", "client_credentials").Matcher())
                        .UsingPost()
                )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(401)
                );

            try
            {
                var token = await _client.RequestTokenAsync();
                Assert.Fail("Should have thrown Exception");
            }
            catch (HttpRequestException) { }
        }
    }
}
