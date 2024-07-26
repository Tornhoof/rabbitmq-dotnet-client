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
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using RabbitMQ.Client.OAuth2;
using Xunit;
using Xunit.Abstractions;

namespace OAuth2Test
{
    public class MockIoAuth2Client : IOAuth2Client
    {
        private readonly ITestOutputHelper _testOutputHelper;
        private IToken _refreshToken;
        private IToken _requestToken;

        public MockIoAuth2Client(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        public IToken RefreshTokenValue
        {
            get { return _refreshToken; }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                _refreshToken = value;
            }
        }

        public IToken RequestTokenValue
        {
            get { return _requestToken; }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                _requestToken = value;
            }
        }

        public Task<IToken> RefreshTokenAsync(IToken initialToken, CancellationToken cancellationToken = default)
        {
            Debug.Assert(ReferenceEquals(_requestToken, initialToken));
            return Task.FromResult(_refreshToken);
        }

        public Task<IToken> RequestTokenAsync(CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_requestToken);
        }
    }

    public class TestOAuth2CredentialsProvider
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public TestOAuth2CredentialsProvider(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void ShouldHaveAName()
        {
            const string name = "aName";
            IOAuth2Client oAuth2Client = new MockIoAuth2Client(_testOutputHelper);
            var provider = new OAuth2ClientCredentialsProvider(name, oAuth2Client);

            Assert.Equal(name, provider.Name);
        }

        [Fact]
        public async Task ShouldRequestTokenWhenAskToRefresh()
        {
            const string newTokenValue = "the_access_token";
            IToken newToken = NewToken(newTokenValue, TimeSpan.FromSeconds(60));
            var oAuth2Client = new MockIoAuth2Client(_testOutputHelper);
            oAuth2Client.RequestTokenValue = newToken;
            var provider =
                new OAuth2ClientCredentialsProvider(nameof(ShouldRequestTokenWhenAskToRefresh), oAuth2Client);

            var creds = await provider.RefreshAsync();

            Assert.Equal(newTokenValue, creds.Password);
        }

        [Fact]
        public async Task ShouldRequestTokenWhenGettingPasswordOrValidUntilForFirstTimeAccess()
        {
            const string accessToken = "the_access_token";
            const string refreshToken = "the_refresh_token";
            IToken firstToken = NewToken(accessToken, refreshToken, TimeSpan.FromSeconds(1));
            var oAuth2Client = new MockIoAuth2Client(_testOutputHelper);
            oAuth2Client.RequestTokenValue = firstToken;
            var provider =
                new OAuth2ClientCredentialsProvider(
                    nameof(ShouldRequestTokenWhenGettingPasswordOrValidUntilForFirstTimeAccess), oAuth2Client);
            var creds = await provider.RefreshAsync();
            Assert.Equal(firstToken.AccessToken, creds.Password);
            Assert.Equal(firstToken.ExpiresIn, creds.ValidUntil.Value);
        }

        [Fact]
        public async Task ShouldRefreshTokenUsingRefreshTokenWhenAvailable()
        {
            const string accessToken = "the_access_token";
            const string refreshToken = "the_refresh_token";
            const string accessToken2 = "the_access_token_2";
            const string refreshToken2 = "the_refresh_token_2";

            IToken firstToken = NewToken(accessToken, refreshToken, TimeSpan.FromSeconds(1));
            IToken refreshedToken = NewToken(accessToken2, refreshToken2, TimeSpan.FromSeconds(60));
            var oAuth2Client = new MockIoAuth2Client(_testOutputHelper);
            oAuth2Client.RequestTokenValue = firstToken;
            var provider =
                new OAuth2ClientCredentialsProvider(
                    nameof(ShouldRequestTokenWhenGettingPasswordOrValidUntilForFirstTimeAccess), oAuth2Client);

            var creds = await provider.RefreshAsync();

            Assert.Equal(firstToken.AccessToken, creds.Password);
            Assert.Equal(firstToken.ExpiresIn, creds.ValidUntil.Value);

            oAuth2Client.RefreshTokenValue = refreshedToken;
            creds = await provider.RefreshAsync();

            Assert.Equal(refreshedToken.AccessToken, creds.Password);
            Assert.Equal(refreshedToken.ExpiresIn, creds.ValidUntil.Value);
        }

        [Fact]
        public async Task ShouldRequestTokenWhenRefreshTokenNotAvailable()
        {
            const string accessToken = "the_access_token";
            const string accessToken2 = "the_access_token_2";
            IToken firstToken = NewToken(accessToken, null, TimeSpan.FromSeconds(1));
            IToken secondToken = NewToken(accessToken2, null, TimeSpan.FromSeconds(60));

            var oAuth2Client = new MockIoAuth2Client(_testOutputHelper);
            oAuth2Client.RequestTokenValue = firstToken;
            var provider = new OAuth2ClientCredentialsProvider(nameof(ShouldRequestTokenWhenRefreshTokenNotAvailable),
                oAuth2Client);

            var creds = await provider.RefreshAsync();

            Assert.Equal(firstToken.AccessToken, creds.Password);
            Assert.Equal(firstToken.ExpiresIn, creds.ValidUntil.Value);

            oAuth2Client.RequestTokenValue = secondToken;
            creds = await provider.RefreshAsync();

            Assert.Equal(secondToken.AccessToken, creds.Password);
            Assert.Equal(secondToken.ExpiresIn, creds.ValidUntil.Value);
        }

        private static Token NewToken(string accessToken, TimeSpan expiresIn)
        {
            var token = new JsonToken(accessToken, string.Empty, expiresIn);
            return new Token(token);
        }

        private static Token NewToken(string accessToken, string refreshToken, TimeSpan expiresIn)
        {
            JsonToken token = new JsonToken(accessToken, refreshToken, expiresIn);
            return new Token(token);
        }
    }
}
