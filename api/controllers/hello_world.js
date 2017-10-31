module.exports = {
  hello
};

async function hello(req, res) {
  let name = req.query.name || 'stranger';
  // this sends back a JSON response which is a single string
  res.json(`Hello, ${name}`);
}
