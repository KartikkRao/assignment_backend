const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { verifyToken } = require('./server'); // Adjust the path as needed

describe('Authentication Logic', () => {


  test('should hash passwords correctly', async () => {
    const password = 'password123';
    const hashedPassword = await bcrypt.hash(password, 10);
    const match = await bcrypt.compare(password, hashedPassword);
    expect(match).toBe(true);
  });

  test('should sign JWT tokens correctly', () => {
    const payload = { id: 'user1', email: 'user@example.com' };
    const token = jwt.sign(payload, process.env.SECRET, { expiresIn: '2h' });
    const decoded = jwt.verify(token, process.env.SECRET);
    expect(decoded.id).toBe(payload.id);
    expect(decoded.email).toBe(payload.email);
  });

  test('should verify tokens correctly', done => {
    const payload = { id: 'user1', email: 'user@example.com' };
    const token = jwt.sign(payload, process.env.SECRET, { expiresIn: '2h' });

    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = {};
    const next = jest.fn();

    verifyToken(req, res, () => {
      expect(req.user.id).toBe(payload.id);
      expect(req.user.email).toBe(payload.email);
      done();
    });
  });
});

