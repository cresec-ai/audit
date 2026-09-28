// Records receipt independently of the recorder, then never answers the call.
const fs = require('node:fs');
const journal = process.argv[2];
fs.writeFileSync(journal + '.pid', String(process.pid));
process.stdin.setEncoding('utf8');
let buffer = '';
process.stdin.on('data', (chunk) => {
  buffer += chunk;
  let end;
  while ((end = buffer.indexOf('\n')) >= 0) {
    fs.appendFileSync(journal, buffer.slice(0, end) + '\n');
    buffer = buffer.slice(end + 1);
  }
});
