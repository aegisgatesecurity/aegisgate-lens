// F-01 isForeignSender logic test (6 cases)
// Tests the sender.id validation logic from service-worker.js

const OWN_EXTENSION_ID = 'aegisgate-lens-extension-id';

function isForeignSender(sender) {
  if (!sender) return true;
  if (!sender.id) return true;
  if (sender.id === '') return true;
  if (sender.id !== OWN_EXTENSION_ID) return true;
  return false;
}

const cases = [
  { sender: undefined, expected: true, name: 'undefined sender' },
  { sender: null, expected: true, name: 'null sender' },
  { sender: {}, expected: true, name: 'empty object' },
  { sender: { id: '' }, expected: true, name: 'empty id' },
  { sender: { id: 'attacker-extension-id' }, expected: true, name: 'wrong id' },
  { sender: { id: OWN_EXTENSION_ID }, expected: false, name: 'correct id' },
];

let allPassed = true;
let passes = 0;
let fails = 0;
for (const c of cases) {
  const actual = isForeignSender(c.sender);
  if (actual !== c.expected) {
    console.log(`FAIL ${c.name} got ${actual} expected ${c.expected}`);
    allPassed = false;
    fails++;
  } else {
    console.log(`PASS ${c.name}`);
    passes++;
  }
}

console.log(`\nResult: ${passes}/${cases.length} pass`);
process.exit(allPassed ? 0 : 1);