-module(tc_user_timeline).

-include("records.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([user_timeline/1]).

user_timeline(UserName) ->
  Request = request(UserName),
  http_request(Request).

http_request(Request) ->
  Url = Request#request.base_url ++ "?" ++ parameter_string(Request),
  httpc:request(Request#request.method, {Url, [{"Authorization", tc_signing:authorization_header(Request)}]}, [], []).

parameter_string(Request) ->
  Sorted = lists:sort(Request#request.params),
  Encoded = lists:map(fun tc_signing:joinparam/1, Sorted),
  tc_signing:joinparams(Encoded).

request(UserName) ->
  Params = [
    {include_entities, "true"},
    {screen_name, UserName}
  ],
  #request{
    method=get,
    secrets=tl_secrets:signing_secrets(),
    params=Params,
    oauth_params=oauth(),
    base_url="https://api.twitter.com/1.1/statuses/user_timeline.json"
  }.

timestamp() ->
  {MegaSecs, Secs, _MicroSecs} = now(),
  integer_to_list(MegaSecs * 1000000 + Secs).

nonce() ->
  Bytes = crypto:rand_bytes(32),
  Encoded = base64:encode_to_string(Bytes),
  strip_nonword(Encoded).

strip_nonword(Str) ->
  re:replace(Str, "[^A-Za-z0-9]", "", [global, {return, list}]).

strip_nonword_test() ->
  ?assertMatch("rzEa3Y5Ove9kWIodkj4DOUBRHiTzPJG9qS1hOP8", strip_nonword("r/zEa3Y5Ove9kWI/odkj4DOUBRHiT+zPJG9+qS1hOP8=")).

user_timeline_test() ->
  inets:start(),
  ssl:start(),
  {ok, {Status, Headers, Body}} = user_timeline("caltrain_news"),
  ssl:stop(),
  inets:stop().


oauth() ->
  [
    {oauth_consumer_key, tl_secrets:oauth_consumer_key()},
    {oauth_nonce, nonce()},
    {oauth_signature_method, "HMAC-SHA1"},
    {oauth_timestamp, timestamp()},
    {oauth_token, tl_secrets:oauth_token()},
    {oauth_version, "1.0"}
  ].
