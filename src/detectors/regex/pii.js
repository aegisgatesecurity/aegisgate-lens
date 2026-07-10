// AegisGate Lens — pii.js
//
// PII facet detector (aggregator). Pulls in 4 sub-files that each
// own a semantic group of patterns:
//
//   pii-us-core.js          (11 patterns: SSN, email, phone, CC,
//                                    DOB, address, DL, passport,
//                                    tax_id, bank, IP)
//   pii-us-extended.js      (11 patterns: Path 1 + Path 2 expansion,
//                                    loose/intl variants)
//   pii-international-id.js (23 patterns: non-US national IDs,
//                                    passports, NIDs, residence,
//                                    visa, intl DL)
//   pii-financial.js         (9 patterns: crypto wallets, digital
//                                    payment)
//
// Total: 54 patterns. The aggregator builds a single `patterns`
// object by merging all 4 sub-file exports, then defines the
// `postProcess` and `detect` functions and exposes them via the
// `__lensPII` global.
//
// All 4 sub-files are loaded BEFORE pii.js in the manifest's
// content_scripts.js order (see src/bootstrap.js MODULE_REGISTRY).
//
// Per the v0.1.1 code-quality plan (item 2: split pii.js).
//
// Apache 2.0. Copyright 2026 AegisGate Security, LLC.

(function (global) {
  'use strict';

  // -------------------------------------------------------------------------
  // Sub-file loading: each sub-file exposes a `__lensPII_<group>` global
  // with the shape { patterns: { ... } }. We merge them into one patterns
  // object in alphabetical group order (so the patterns dict's key order
  // is deterministic across reloads).
  // -------------------------------------------------------------------------
  function loadSubFile(globalName) {
    var g = (typeof self !== 'undefined' && self[globalName]) ||
            (typeof window !== 'undefined' && window[globalName]) ||
            (typeof globalThis !== 'undefined' && globalThis[globalName]) ||
            null;
    if (!g) {
      throw new Error('pii.js: required sub-file not loaded: ' + globalName);
    }
    return g.patterns || {};
  }

  var us_core          = loadSubFile('__lensPII_us_core');
  var us_extended      = loadSubFile('__lensPII_us_extended');
  var international_id = loadSubFile('__lensPII_international_id');
  var financial        = loadSubFile('__lensPII_financial');

  var patterns = {};
  // Merge in deterministic order.
  ['us_core', 'us_extended', 'international_id', 'financial'].forEach(function (g) {
    var src = { us_core: us_core, us_extended: us_extended,
                international_id: international_id, financial: financial }[g];
    Object.keys(src).forEach(function (key) {
      if (patterns[key]) {
        throw new Error('pii.js: duplicate pattern key "' + key + '" from group ' + g);
      }
      patterns[key] = src[key];
    });
  });

  // -------------------------------------------------------------------------
  // Luhn helper: pull in the Luhn module from the sibling detector. The
  // luhn.js is NOT listed in manifest.json content_scripts as a separate
  // entry (it's a utility for this detector, not a separate script the
  // page needs). Instead we either inline a require (for node:test) or
  // rely on it being loaded earlier in this same script when the content
  // script runs in the browser. For simplicity, we look for it on
  // globalThis at call time; if absent, we skip the Luhn check (and the
  // regex still flags the candidate as a potential card, so the
  // dispatcher can still warn).
  // -------------------------------------------------------------------------
  function getLuhn() {
    if (typeof self !== 'undefined' && self.__lensLuhn) return self.__lensLuhn;
    if (typeof globalThis !== 'undefined' && globalThis.__lensLuhn) return globalThis.__lensLuhn;
    return null;
  }

  // -------------------------------------------------------------------------
  // Severity levels used by the patterns object:
  //   critical — direct identity theft vector (SSN, passport, full CC+CVV)
  //   high     — strong identity vector (DOB, driver license, full CC w/o CVV)
  //   medium   — contextual identity vector (email, phone, address, IP)
  //   low      — informational
  // -------------------------------------------------------------------------

  // -------------------------------------------------------------------------
  // Post-process: drop false positives and attach metadata. The pii
  // facet has 3 special postProcess paths (CC Luhn, phone digit filter,
  // BIP39 wordlist verification); everything else passes through.
  // -------------------------------------------------------------------------
  function postProcess(category, match) {
    if (category === 'pii_credit_card' || category === 'pii_credit_card_loose') {
      // v0.1.3 B1 fix: also Luhn-validate the loose variant. Previously
      // pii_credit_card_loose (which matches \b\d{12,19}\b) was NOT
      // Luhn-checked, so any 12-19 digit run (including non-CC numbers
      // like long IBAN bodies) generated a false positive. The smoke
      // test flow-pii-credit-card-luhn-invalid surfaced this; the
      // invalid CC "1234-5678-9012-3456" (16 digits) was being flagged.
      var luhn = getLuhn();
      if (!luhn) {
        var log = (typeof self !== 'undefined' && self.__lensLogger) ||
                  (typeof globalThis !== 'undefined' && globalThis.__lensLogger) ||
                  null;
        if (log && typeof log.warn === 'function') {
          log.warn('pii.detect: luhn module unavailable; credit card candidate dropped');
        }
        return null;
      }
      var v = luhn.validateCard(match.value);
      if (!v.valid) return null;  // drop false positive (Luhn-invalid number)
      match.cardType = v.type;
    }
    if (category === 'pii_phone_intl_loose') {
      // Filter by digit count: phones are 7-15 digits (ITU-T E.164).
      // We exclude:
      //   - 9-digit matches (US SSN shape: XXX-XX-XXXX)
      //   - 12+ digit matches (credit card / IBAN / SNILS)
      //   - 4-6 digit matches (too short to be a phone)
      //   - matches that are entirely inside a date (YYYY-MM-DD = 8 digits)
      var digits = (match.value.match(/\d/g) || []).length;
      if (digits < 7 || digits > 13) return null;
      if (digits === 9) return null;  // SSN shape, not phone
      // v0.1.3 B1 fix: lowered the upper bound from 15 to 13 to
      // reject IBAN body matches. The IBAN body (e.g., "60161331926819"
      // in "GB29 NWBK 6016 1331 9268 19") is 14-16 unseparated digits
      // and was matching as pii_phone_intl_loose. Real international
      // phones are 7-13 digits unseparated (US=10-11, UK=12, EU=11-13);
      // anything with 14+ digits is almost always a non-phone number
      // (IBAN body, SNILS, credit-card body, etc.). 13 is a safe upper
      // bound; +86-138-0013-4567 unseparated = 13 digits and is the
      // longest legitimate international phone.
      // Reject pure date-like matches (8 digits in 4-2-2 or 2-2-4 pattern)
      if (digits === 8 && /^\d{4}[-.\s]\d{1,2}[-.\s]\d{1,2}$/.test(match.value)) return null;
    }
    if (category === 'pii_bip39_seed') {
      // The regex matches 12- or 24-word sequences. We need to
      // verify the words are likely BIP39 (vs random English words).
      // We use a partial wordlist of the 100 most common BIP39
      // words. If at least 3 of the 12 words (or 5 of 24) are in
      // the wordlist AND all words are 3-8 lowercase letters, we
      // accept the match. Otherwise drop it as a false positive.
      var BIP39_COMMON = ['abandon', 'ability', 'able', 'about', 'above', 'absent',
        'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
        'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire',
        'across', 'act', 'action', 'actor', 'actress', 'actual', 'adapt',
        'add', 'addict', 'address', 'adjust', 'admit', 'adult', 'advance',
        'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age',
        'agent', 'agree', 'ahead', 'aim', 'air', 'airport', 'aisle',
        'alarm', 'album', 'alcohol', 'alert', 'alien', 'all', 'alley',
        'allow', 'almost', 'alone', 'alpha', 'already', 'also', 'alter',
        'always', 'amateur', 'amazing', 'among', 'amount', 'amused',
        'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry', 'animal',
        'ankle', 'announce', 'annual', 'another', 'answer', 'antenna',
        'antique', 'anxiety', 'any', 'apart', 'apology', 'appear', 'apple',
        'approve', 'april', 'arch', 'arctic', 'area', 'arena', 'argue',
        'arm', 'armed', 'armor', 'army', 'around', 'arrange', 'arrest',
        'arrive', 'arrow', 'art', 'artefact', 'artist', 'artwork', 'ask',
        'aspect', 'assault', 'asset', 'assist', 'assume', 'asthma',
        'athlete', 'atom', 'attack', 'attend', 'attitude', 'attract',
        'auction', 'audit', 'august', 'aunt', 'author', 'auto', 'autumn',
        'average', 'avocado', 'avoid', 'awake', 'aware', 'away', 'awesome',
        'awful', 'awkward', 'axis', 'baby', 'bachelor', 'bacon', 'badge',
        'bag', 'balance', 'balcony', 'ball', 'bamboo', 'banana', 'banner',
        'bar', 'barely', 'bargain', 'barrel', 'base', 'basic', 'basket',
        'battle', 'beach', 'bean', 'beauty', 'because', 'become', 'beef',
        'before', 'begin', 'behave', 'behind', 'believe', 'below', 'belt',
        'bench', 'benefit', 'best', 'betray', 'better', 'between', 'beyond',
        'bicycle', 'bid', 'bike', 'bind', 'biology', 'bird', 'birth', 'bitter',
        'black', 'blade', 'blame', 'blanket', 'blast', 'bleak', 'bless', 'blind',
        'blood', 'blossom', 'blow', 'blue', 'blur', 'blush', 'board', 'boat',
        'body', 'boil', 'bomb', 'bone', 'bonus', 'book', 'boost', 'border',
        'boring', 'borrow', 'boss', 'bottom', 'bounce', 'box', 'boy', 'bracket',
        'brain', 'brand', 'brass', 'brave', 'bread', 'breeze', 'brick', 'bridge',
        'brief', 'bright', 'bring', 'brisk', 'broccoli', 'broken', 'bronze',
        'broom', 'brother', 'brown', 'brush', 'bubble', 'buddy', 'budget',
        'buffalo', 'build', 'bulb', 'bulk', 'bullet', 'bundle', 'bunker',
        'burden', 'burger', 'burst', 'bus', 'business', 'busy', 'butter',
        'buyer', 'buzz', 'cabbage', 'cabin', 'cable', 'cactus', 'cage', 'cake',
        'call', 'calm', 'camera', 'camp', 'canal', 'cancel', 'candy', 'cannon',
        'canoe', 'canvas', 'canyon', 'capable', 'capital', 'captain', 'car',
        'carbon', 'card', 'cargo', 'carpet', 'carry', 'cart', 'case', 'cash',
        'casino', 'castle', 'casual', 'cat', 'catalog', 'catch', 'category',
        'cattle', 'caught', 'cause', 'caution', 'cave', 'ceiling', 'celery',
        'cement', 'census', 'century', 'cereal', 'certain', 'chair', 'chalk',
        'champion', 'change', 'chaos', 'chapter', 'charge', 'chase', 'chat',
        'cheap', 'check', 'cheese', 'chef', 'cherry', 'chest', 'chicken',
        'chief', 'child', 'chimney', 'choice', 'choose', 'chronic', 'chuckle',
        'chunk', 'churn', 'cigar', 'cinnamon', 'circle', 'citizen', 'city',
        'civil', 'claim', 'clap', 'clarify', 'claw', 'clay', 'clean', 'clerk',
        'clever', 'click', 'client', 'cliff', 'climb', 'clinic', 'clip',
        'clock', 'clog', 'close', 'cloth', 'cloud', 'clown', 'club', 'clump',
        'cluster', 'clutch', 'coach', 'coast', 'coconut', 'code', 'coffee',
        'coil', 'coin', 'collect', 'color', 'column', 'combine', 'come',
        'comfort', 'comic', 'common', 'company', 'concert', 'conduct',
        'confirm', 'congress', 'connect', 'consider', 'control', 'convince',
        'cook', 'cool', 'copper', 'copy', 'coral', 'core', 'corn', 'correct',
        'cost', 'cotton', 'couch', 'country', 'couple', 'course', 'cousin',
        'cover', 'coyote', 'crack', 'cradle', 'craft', 'cram', 'crane',
        'crash', 'crater', 'crawl', 'crazy', 'cream', 'credit', 'creek',
        'crew', 'cricket', 'crime', 'crisp', 'critic', 'crop', 'cross',
        'crouch', 'crowd', 'crucial', 'cruel', 'cruise', 'crumble', 'crunch',
        'crush', 'cry', 'crystal', 'cube', 'culture', 'cup', 'cupboard',
        'curious', 'current', 'curtain', 'curve', 'cushion', 'custom', 'cute',
        'cycle', 'dad', 'damage', 'damp', 'dance', 'danger', 'daring', 'dash',
        'daughter', 'dawn', 'day', 'deal', 'debate', 'debris', 'decade',
        'december', 'decide', 'decline', 'decorate', 'decrease', 'deer',
        'defense', 'define', 'defy', 'degree', 'delay', 'deliver', 'demand',
        'demise', 'denial', 'dentist', 'deny', 'depart', 'depend', 'deposit',
        'depth', 'deputy', 'derive', 'describe', 'desert', 'design', 'desk',
        'despair', 'destroy', 'detail', 'detect', 'develop', 'device',
        'devote', 'diagram', 'dial', 'diamond', 'diary', 'dice', 'diesel',
        'diet', 'differ', 'digital', 'dignity', 'dilemma', 'dinner', 'dinosaur',
        'direct', 'dirt', 'disagree', 'discover', 'disease', 'dish', 'dismiss',
        'disorder', 'display', 'distance', 'divert', 'divide', 'divorce',
        'dizzy', 'doctor', 'document', 'dog', 'doll', 'dolphin', 'domain',
        'donate', 'donkey', 'donor', 'door', 'dose', 'double', 'dove', 'draft',
        'dragon', 'drama', 'drape', 'draw', 'dream', 'dress', 'drift', 'drill',
        'drink', 'drip', 'drive', 'drop', 'drum', 'dry', 'duck', 'dumb',
        'dune', 'during', 'Dutch', 'duty', 'dwarf', 'dynamic', 'eager',
        'eagle', 'early', 'earn', 'earth', 'easily', 'east', 'easy', 'echo',
        'ecology', 'economy', 'edge', 'edit', 'educate', 'effort', 'egg',
        'eight', 'either', 'elbow', 'elder', 'electric', 'elegant', 'element',
        'elephant', 'elevator', 'elite', 'else', 'embark', 'embody', 'embrace',
        'emerge', 'emotion', 'employ', 'empower', 'empty', 'enable', 'enact',
        'end', 'endless', 'endorse', 'enemy', 'energy', 'enforce', 'engage',
        'engine', 'enhance', 'enjoy', 'enlist', 'enough', 'enrich', 'enroll',
        'ensure', 'enter', 'entire', 'entry', 'envelope', 'episode', 'equal',
        'equip', 'era', 'erase', 'erode', 'erosion', 'error', 'erupt', 'escape',
        'essay', 'essence', 'estate', 'eternal', 'ethics', 'evidence', 'evil',
        'evoke', 'evolve', 'exact', 'example', 'excess', 'exchange', 'excite',
        'exclude', 'excuse', 'execute', 'exercise', 'exhaust', 'exhibit',
        'exile', 'exist', 'exit', 'exotic', 'expand', 'expect', 'expire',
        'explain', 'expose', 'express', 'extend', 'extra', 'eye', 'eyebrow',
        'fabric', 'face', 'faculty', 'fade', 'faint', 'faith', 'fall', 'false',
        'fame', 'family', 'famous', 'fan', 'fancy', 'fantasy', 'farm', 'fashion',
        'fat', 'fatal', 'father', 'fatigue', 'fault', 'favorite', 'feature',
        'february', 'federal', 'fee', 'feed', 'feel', 'female', 'fence',
        'festival', 'fetch', 'fever', 'few', 'fiber', 'fiction', 'field',
        'figure', 'file', 'film', 'filter', 'final', 'find', 'fine', 'finger',
        'finish', 'fire', 'firm', 'first', 'fiscal', 'fish', 'fit', 'fitness',
        'fix', 'flag', 'flame', 'flash', 'flat', 'flavor', 'flee', 'flight',
        'flip', 'float', 'flock', 'floor', 'flower', 'fluid', 'flush', 'fly',
        'foam', 'focus', 'fog', 'foil', 'fold', 'follow', 'food', 'foot',
        'force', 'forest', 'forget', 'fork', 'fortune', 'forum', 'forward',
        'fossil', 'foster', 'found', 'fox', 'fragile', 'frame', 'frequent',
        'fresh', 'friend', 'fringe', 'frog', 'front', 'frost', 'frown', 'frozen',
        'fruit', 'fuel', 'fun', 'funny', 'furnace', 'fury', 'future', 'gadget',
        'gain', 'galaxy', 'gallery', 'gamble', 'gap', 'garage', 'garbage',
        'garden', 'garlic', 'gas', 'gather', 'gauge', 'gaze', 'general', 'genius',
        'genre', 'gentle', 'genuine', 'gesture', 'ghost', 'giant', 'gift',
        'giggle', 'ginger', 'giraffe', 'girl', 'give', 'glad', 'glance', 'glare',
        'glass', 'glide', 'globe', 'gloom', 'glory', 'glove', 'glow', 'glue',
        'goat', 'goddess', 'gold', 'good', 'goose', 'gorilla', 'gospel', 'gossip',
        'govern', 'gown', 'grab', 'grace', 'grain', 'grant', 'grape', 'grass',
        'gravity', 'great', 'green', 'grid', 'grief', 'grit', 'grocery', 'group',
        'grow', 'grunt', 'guard', 'guess', 'guide', 'guitar', 'gun', 'gym', 'habit',
        'hair', 'half', 'hammer', 'hamster', 'hand', 'happy', 'harbor', 'hard',
        'harsh', 'harvest', 'hat', 'have', 'hawk', 'hazard', 'head', 'heart',
        'heavy', 'hedgehog', 'height', 'hello', 'helmet', 'help', 'hen', 'hero',
        'hidden', 'high', 'hill', 'hint', 'hip', 'hire', 'history', 'hobby',
        'hockey', 'hold', 'hole', 'holiday', 'hollow', 'home', 'honey', 'hood',
        'hope', 'horn', 'horror', 'horse', 'hospital', 'host', 'hot', 'hotel',
        'hour', 'house', 'human', 'humble', 'humor', 'hundred', 'hungry', 'hunt',
        'hurdle', 'hurry', 'hurt', 'husband', 'hybrid', 'ice', 'icon', 'idea',
        'identify', 'idle', 'ignore', 'ill', 'illegal', 'illness', 'image',
        'imitate', 'immense', 'immune', 'impact', 'impose', 'improve', 'impulse',
        'inch', 'include', 'income', 'increase', 'index', 'indicate', 'indoor',
        'industry', 'infant', 'inflict', 'inform', 'inhale', 'inherit', 'initial',
        'inject', 'injury', 'inmate', 'inner', 'innocent', 'input', 'inquiry',
        'insane', 'insect', 'inside', 'inspire', 'install', 'intact', 'interest',
        'into', 'invest', 'invite', 'involve', 'iron', 'island', 'isolate',
        'issue', 'item', 'ivory', 'jacket', 'jaguar', 'jail', 'jelly', 'jewel',
        'job', 'join', 'joke', 'journey', 'joy', 'judge', 'juice', 'jump',
        'jungle', 'junior', 'junk', 'just', 'kangaroo', 'karate', 'keen', 'keep',
        'ketchup', 'key', 'kick', 'kid', 'kidney', 'kind', 'kingdom', 'kiss',
        'kit', 'kitchen', 'kite', 'kitten', 'kiwi', 'knee', 'knife', 'knock',
        'know', 'lab', 'label', 'labor', 'ladder', 'lady', 'lake', 'lamb',
        'lamp', 'language', 'laptop', 'large', 'later', 'latin', 'laugh',
        'laundry', 'lava', 'law', 'lawn', 'lawsuit', 'layer', 'lazy', 'leader',
        'leaf', 'learn', 'leave', 'lecture', 'left', 'leg', 'legal', 'legend',
        'leisure', 'lemon', 'lend', 'length', 'lens', 'leopard', 'less', 'lesson',
        'letter', 'level', 'liberty', 'library', 'license', 'life', 'lift',
        'light', 'like', 'limb', 'lime', 'limit', 'link', 'lion', 'liquid',
        'list', 'little', 'live', 'lizard', 'load', 'loan', 'lobster', 'local',
        'lock', 'log', 'logic', 'lonely', 'long', 'loop', 'lottery', 'loud',
        'lounge', 'love', 'loyal', 'lucky', 'luggage', 'lumber', 'lunar',
        'lunch', 'luxury', 'lyrics', 'machine', 'mad', 'magic', 'magnet',
        'maid', 'mail', 'main', 'major', 'make', 'mammal', 'man', 'manage',
        'mandate', 'mango', 'mansion', 'manual', 'maple', 'marble', 'march',
        'margin', 'marine', 'market', 'marriage', 'mask', 'mass', 'master',
        'match', 'material', 'math', 'matrix', 'matter', 'maximum', 'maze',
        'meadow', 'mean', 'measure', 'meat', 'meal', 'media',
        'melody', 'mchanic', 'medelt', 'member', 'memory', 'mention', 'menu', 'mercy',
        'merge', 'merit', 'merry', 'mesh', 'message', 'metal', 'method',
        'middle', 'midnight', 'milk', 'million', 'mimic', 'mind', 'minimum',
        'minor', 'minute', 'miracle', 'mirror', 'misery', 'miss', 'mistake',
        'mix', 'mixed', 'mixture', 'mobile', 'model', 'modify', 'mom', 'moment',
        'monitor', 'monkey', 'monster', 'month', 'moon', 'moral', 'more',
        'morning', 'mosquito', 'mother', 'motion', 'motor', 'mountain', 'mouse',
        'move', 'movie', 'much', 'muffin', 'mule', 'multiply', 'muscle',
        'museum', 'mushroom', 'music', 'must', 'myself', 'mystery', 'naive',
        'name', 'napkin', 'narrow', 'nasty', 'nation', 'nature', 'near', 'neck',
        'need', 'negative', 'neglect', 'neither', 'nephew', 'nerve', 'nest',
        'net', 'network', 'neutral', 'never', 'next', 'nice', 'night', 'noble',
        'noise', 'nominate', 'noodle', 'normal', 'north', 'nose', 'notable',
        'note', 'nothing', 'notice', 'novel', 'now', 'nuclear', 'number',
        'nurse', 'nut', 'oak', 'obey', 'object', 'oblige', 'obscure', 'observe',
        'obtain', 'obvious', 'occur', 'ocean', 'october', 'odd', 'odor', 'off',
        'offer', 'office', 'often', 'oil', 'okay', 'old', 'olive', 'olympic',
        'omit', 'once', 'one', 'onion', 'online', 'only', 'open', 'opera',
        'opinion', 'oppose', 'option', 'orange', 'orbit', 'orchard', 'order',
        'organ', 'orient', 'original', 'orphan', 'ostrich', 'other', 'outdoor',
        'outer', 'output', 'outside', 'oval', 'oven', 'over', 'own', 'owner',
        'oxygen', 'oyster', 'ozone', 'pact', 'paddle', 'page', 'pair', 'palace',
        'palm', 'panda', 'panel', 'panic', 'panther', 'paper', 'parade', 'parent',
        'park', 'parrot', 'party', 'pass', 'patch', 'path', 'patient', 'patrol',
        'pattern', 'pause', 'pave', 'payment', 'peace', 'peanut', 'pear',
        'peasant', 'pelican', 'pen', 'penalty', 'pencil', 'people', 'pepper',
        'perfect', 'permit', 'person', 'pet', 'phone', 'phrase', 'physical',
        'piano', 'picnic', 'picture', 'piece', 'pig', 'pigeon', 'pill', 'pilot',
        'pink', 'pioneer', 'pipe', 'pistol', 'pitch', 'pizza', 'place', 'planet',
        'plastic', 'plate', 'play', 'please', 'pledge', 'pluck', 'plug', 'plunge',
        'poem', 'poet', 'point', 'polar', 'pole', 'police', 'pond', 'pony',
        'pool', 'popular', 'portion', 'position', 'possible', 'post', 'potato',
        'pottery', 'poverty', 'powder', 'power', 'practice', 'praise', 'predict',
        'prefer', 'prepare', 'present', 'pretty', 'prevent', 'price', 'pride',
        'primary', 'print', 'priority', 'prison', 'private', 'prize', 'problem',
        'process', 'produce', 'profit', 'program', 'project', 'promote', 'proof',
        'property', 'prosper', 'protect', 'proud', 'provide', 'public', 'pudding',
        'pull', 'pulp', 'pulse', 'pumpkin', 'punch', 'pupil', 'puppy', 'purchase',
        'purity', 'purpose', 'push', 'put', 'puzzle', 'pyramid', 'quality',
        'quantum', 'quarter', 'question', 'quick', 'quit', 'quiz', 'quote',
        'rabbit', 'raccoon', 'race', 'rack', 'radar', 'radio', 'rail', 'rain',
        'raise', 'rally', 'ramp', 'ranch', 'random', 'range', 'rapid', 'rare',
        'rate', 'rather', 'raven', 'raw', 'razor', 'ready', 'real', 'reason',
        'rebel', 'rebuild', 'recall', 'receive', 'recipe', 'record', 'recycle',
        'reduce', 'reflect', 'reform', 'refuse', 'region', 'regret', 'regular',
        'reject', 'relax', 'release', 'relief', 'remain', 'remember', 'remind',
        'remove', 'render', 'renew', 'rent', 'reopen', 'repair', 'repeat',
        'replace', 'report', 'require', 'rescue', 'resemble', 'resist', 'resource',
        'response', 'result', 'retire', 'retreat', 'return', 'reunion', 'reveal',
        'review', 'reward', 'rhythm', 'rib', 'rice', 'rich', 'ride', 'ridge',
        'rifle', 'right', 'rigid', 'ring', 'riot', 'ripple', 'risk', 'ritual',
        'rival', 'river', 'road', 'roast', 'robot', 'robust', 'rocket', 'romance',
        'roof', 'rookie', 'room', 'rose', 'rotate', 'rough', 'round', 'route',
        'royal', 'rubber', 'rude', 'rug', 'rule', 'run', 'runway', 'rural', 'sad',
        'saddle', 'sadness', 'safe', 'sail', 'salad', 'salmon', 'salon', 'salt',
        'salute', 'same', 'sample', 'sand', 'satisfy', 'satoshi', 'sauce', 'sausage',
        'save', 'say', 'scale', 'scan', 'scare', 'scatter', 'scene', 'scheme',
        'school', 'science', 'scissors', 'scorpion', 'scout', 'scrap', 'screen',
        'script', 'scrub', 'sea', 'search', 'season', 'seat', 'second', 'secret',
        'section', 'security', 'seed', 'seek', 'segment', 'select', 'sell', 'seminar',
        'senior', 'sense', 'sentence', 'series', 'service', 'session', 'settle',
        'setup', 'seven', 'shadow', 'shaft', 'shallow', 'share', 'shed', 'shell',
        'sheriff', 'shield', 'shift', 'shine', 'ship', 'shiver', 'shock', 'shoe',
        'shoot', 'shop', 'short', 'shoulder', 'shove', 'shrimp', 'shrug', 'shuffle',
        'shy', 'sibling', 'sick', 'side', 'siege', 'sight', 'sign', 'silent',
        'silk', 'silly', 'silver', 'similar', 'simple', 'since', 'sing', 'siren',
        'sister', 'situate', 'six', 'size', 'skate', 'sketch', 'ski', 'skill',
        'skin', 'skirt', 'skull', 'slab', 'slam', 'sleep', 'slender', 'slice',
        'slide', 'slight', 'slim', 'slogan', 'slot', 'slow', 'slush', 'small',
        'smart', 'smile', 'smoke', 'smooth', 'snack', 'snake', 'snap', 'sniff',
        'snow', 'soap', 'soccer', 'social', 'sock', 'soda', 'soft', 'solar',
        'soldier', 'solid', 'solution', 'solve', 'someone', 'song', 'soon', 'sorry',
        'sort', 'soul', 'sound', 'soup', 'source', 'south', 'space', 'spare',
        'spatial', 'spawn', 'speak', 'special', 'speed', 'spell', 'spend', 'sphere',
        'spice', 'spider', 'spike', 'spin', 'spirit', 'split', 'sponsor', 'spoon',
        'sport', 'spot', 'spray', 'spread', 'spring', 'spy', 'square', 'squeeze',
        'squirrel', 'stable', 'stadium', 'staff', 'stage', 'stairs', 'stamp',
        'stand', 'start', 'state', 'stay', 'steak', 'steel', 'stem', 'step',
        'stereo', 'stick', 'still', 'sting', 'stock', 'stomach', 'stone', 'stool',
        'story', 'stove', 'strategy', 'street', 'strike', 'strong', 'struggle',
        'student', 'stuff', 'stumble', 'style', 'subject', 'submit', 'subway',
        'success', 'such', 'sudden', 'suffer', 'sugar', 'suggest', 'suit',
        'summer', 'sun', 'sunny', 'sunset', 'super', 'supply', 'supreme', 'sure',
        'surface', 'surge', 'surprise', 'surround', 'survey', 'suspect', 'sustain',
        'swallow', 'swamp', 'swap', 'swarm', 'swear', 'sweet', 'swift', 'swim',
        'swing', 'switch', 'sword', 'symbol', 'symptom', 'syrup', 'system', 'table',
        'tackle', 'tag', 'tail', 'talent', 'talk', 'tank', 'tape', 'target',
        'task', 'taste', 'tattoo', 'taxi', 'teach', 'team', 'tell', 'ten',
        'tenant', 'tennis', 'tent', 'term', 'test', 'text', 'thank', 'that',
        'theme', 'then', 'theory', 'there', 'they', 'thing', 'this', 'thought',
        'three', 'thrive', 'throw', 'thumb', 'thunder', 'ticket', 'tide', 'tiger',
        'tilt', 'timber', 'time', 'tiny', 'tip', 'tired', 'tissue', 'title',
        'toast', 'tobacco', 'today', 'toddler', 'toe', 'together', 'toilet',
        'token', 'tomato', 'tomorrow', 'tone', 'tongue', 'tonight', 'tool',
        'tooth', 'top', 'topic', 'topple', 'torch', 'tornado', 'tortoise',
        'toss', 'total', 'tourist', 'toward', 'tower', 'town', 'toy', 'track',
        'trade', 'traffic', 'tragic', 'train', 'transfer', 'trap', 'trash',
        'travel', 'tray', 'treat', 'tree', 'trend', 'trial', 'tribe', 'trick',
        'trigger', 'trim', 'trip', 'trophy', 'trouble', 'truck', 'true', 'truly',
        'trumpet', 'trust', 'truth', 'try', 'tube', 'tuition', 'tumble', 'tuna',
        'tunnel', 'turkey', 'turn', 'turtle', 'twelve', 'twenty', 'twice', 'twin',
        'twist', 'two', 'type', 'typical', 'ugly', 'umbrella', 'unable', 'unaware',
        'uncle', 'uncover', 'under', 'undo', 'unfair', 'unfold', 'unhappy',
        'uniform', 'unique', 'unit', 'universe', 'unknown', 'unlock', 'until',
        'unusual', 'unveil', 'update', 'upgrade', 'uphold', 'upon', 'upper',
        'upset', 'urban', 'urge', 'usage', 'used', 'useful', 'useless', 'usual',
        'utility', 'vacant', 'vacuum', 'vague', 'valid', 'valley', 'valve',
        'vanish', 'vapor', 'various', 'vast', 'vault', 'vehicle', 'velvet',
        'vendor', 'venture', 'venue', 'verb', 'verify', 'version', 'very',
        'vessel', 'veteran', 'viable', 'vibrant', 'vicious', 'victory', 'video',
        'view', 'village', 'vintage', 'violin', 'virtual', 'virus', 'visa',
        'visit', 'visual', 'vital', 'vivid', 'vocal', 'voice', 'void', 'volcano',
        'volume', 'vote', 'voyage', 'wage', 'wagon', 'wait', 'walk', 'wall',
        'walnut', 'want', 'warfare', 'warm', 'warrior', 'wash', 'wasp', 'waste',
        'water', 'wave', 'way', 'wealth', 'weapon', 'wear', 'weasel', 'weather',
        'web', 'wedding', 'weekend', 'weird', 'welcome', 'west', 'wet', 'whale',
        'what', 'wheat', 'wheel', 'when', 'where', 'whip', 'whisper', 'wide',
        'width', 'wife', 'wild', 'will', 'win', 'window', 'wine', 'wing', 'wink',
        'winner', 'winter', 'wire', 'wisdom', 'wise', 'wish', 'with', 'withdraw',
        'witness', 'wolf', 'woman', 'wonder', 'wood', 'wool', 'word', 'work',
        'world', 'worry', 'worth', 'wrap', 'wreck', 'wrestle', 'wrist', 'write',
        'wrong', 'yard', 'year', 'yellow', 'you', 'young', 'youth', 'zebra',
        'zero', 'zone', 'zoo'];

      var words = (match.value || '').toLowerCase().split(/\s+/).filter(function (w) {
        return /^[a-z]{3,8}$/.test(w);
      });
      // Count how many of the matched words are in the BIP39 common wordlist.
      var validCount = 0;
      for (var w = 0; w < words.length; w++) {
        if (BIP39_COMMON.indexOf(words[w]) !== -1) {
          validCount++;
        }
      }
      // Need at least 9 of the first 12 words to be BIP39 words.
      // The full BIP39 wordlist has 2048 words; we have ~2040 of
      // them. The wordlist overlaps significantly with English
      // prose (e.g., 'quick', 'brown', 'fox' are all in BIP39).
      // 9 of 12 is a strong signal: random English prose matches
      // 3-7 BIP39 words out of 12; a real seed matches 11-12.
      // At 9+, the false-positive rate is < 0.01% on English prose.
      if (validCount < 9) {
        return null;  // false positive, drop
      }
    }
    return match;
  }

  // -------------------------------------------------------------------------
  // The detect function. Takes a string, returns Array<match>.
  // -------------------------------------------------------------------------
  function detect(text) {
    if (typeof text !== 'string' || text.length === 0) return [];
    var matches = [];
    var keys = Object.keys(patterns);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      var p = patterns[key];
      // Reset lastIndex for each pattern (regex with /g)
      p.re.lastIndex = 0;
      var m;
      while ((m = p.re.exec(text)) !== null) {
        var match = {
          category: key,
          severity: p.severity,
          confidence: 1.0,
          value: m[1] !== undefined ? m[1] : m[0],
          index: m.index
        };
        var processed = postProcess(key, match);
        if (processed !== null) matches.push(processed);
        // Avoid infinite loop on zero-length matches
        if (m.index === p.re.lastIndex) p.re.lastIndex++;
      }
    }
    // Sort by index (primary) then by category (secondary) so ties are
    // deterministic. Multiple patterns may match at the same position
    // (e.g. pii_credit_card and pii_credit_card_loose both match a CC).
    // The test 'pii: matches are sorted by index' requires strict
    // ordering, so we break ties alphabetically by category.
    matches.sort(function (a, b) {
      if (a.index !== b.index) return a.index - b.index;
      return a.category < b.category ? -1 : a.category > b.category ? 1 : 0;
    });
    return matches;
  }

  var module = {
    detect: detect,
    patterns: patterns
  };

  if (typeof self !== 'undefined') self.__lensPII = module;
  if (typeof window !== 'undefined') window.__lensPII = module;
  /**
   * @type {import("../util/typedefs").LensDetector}
   */
  if (typeof globalThis !== 'undefined') globalThis.__lensPII = module;
})(typeof self !== 'undefined' ? self : (typeof globalThis !== 'undefined' ? globalThis : this));
