import AuthTkt from '../src/index.mjs';
import assert from 'assert';
import { decode } from 'urlencode';

describe('AuthTkt', function () {
  it('Create new token and then validate', function () {
    const auth_tkt = new AuthTkt();
    auth_tkt.setOptions({
      "token_key": "123456",
      "check_ip": false
    });
    const token = auth_tkt.tokenCreate(3, 'test_token', {"user_id": 200}, {
      time: 123456,
      ip: '127.0.0.1'
    });
    //console.log('Token:', token);
    assert.notEqual(token, null);
    const validated = auth_tkt.tokenValidate(decode(token));
    //console.log('Validated:', validated);
    assert.notEqual(validated, false);
    assert.equal(validated['id'], 3);
    assert.equal(validated['token'], 'test_token');
    assert.deepEqual(validated['data'], {"user_id": 200});
  });
});