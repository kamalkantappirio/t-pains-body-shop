const controller = require('./hello_world');
const mockHttp = require('node-mocks-http');

const req = mockHttp.createRequest();
const res = mockHttp.createResponse();

describe('controllers/hello_world', () => {
  it('should return a /hello response', () => {
    controller.hello(req, res);
    expect(res.statusCode).toBe(200);
    expect(res._headers['Content-Type']).toBe('application/json');
  });
});
