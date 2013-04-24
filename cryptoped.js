/**
 * Created with JetBrains WebStorm.
 * User: dtudury
 * Date: 4/24/13
 * Time: 11:22 AM
 * To change this template use File | Settings | File Templates.
 */

(function (define) {
    define(function () {

        var _K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

        crytoped.sha256 = sha256;
        crytoped.hmac = hmac;
        crytoped.pbkdf2 = pbkdf2;

        function crytoped() {
        }

        function pbkdf2(password, salt, iterations, keyLength) {
            var keyWords = _charStringToWords(password);
            var output = [];
            var keyIndex = 0;
            while (keyIndex < keyLength / 32) {
                keyIndex++;
                var message = salt + String.fromCharCode((keyIndex >>> 24) & 0xff) + String.fromCharCode((keyIndex >>> 16) & 0xff) + String.fromCharCode((keyIndex >>> 8) & 0xff) + String.fromCharCode((keyIndex >>> 0) & 0xff);
                var u = _hmacWords(keyWords, _charStringToWords(message + "\x80"), message.length * 8);
                var ui = u;
                for (var i = 1; i < iterations; i++) {
                    ui = _hmacWords(keyWords, ui.concat(0x80000000), 256);
                    for (var j = 0; j < u.length; j++) {
                        u[j] ^= ui[j];
                    }
                }
                output = output.concat(u);
            }
            return output.slice(0, Math.ceil(keyLength / 4));
        }

        function hmac(key, message) {
            if (key.length >= 64) {
                return _hmacWords(sha256(key), _charStringToWords(message + "\x80"), message.length * 8);
            } else {
                return _hmacWords(_charStringToWords(key), _charStringToWords(message + "\x80"), message.length * 8);
            }
        }

        function sha256(message) {
            return _hashWords(_charStringToWords(message + "\x80"), message.length * 8);
        }

        function _hmacWords(keyWords, messageWords, messageBits) {
            while (keyWords.length < 16) keyWords.push(0);
            var oKeyPad = [];
            var iKeyPad = [];
            for (var i = 0; i < 16; i++) {
                var keyWord = keyWords[i] >>> 0;
                oKeyPad[i] = (keyWord ^ 0x5c5c5c5c);
                iKeyPad[i] = (keyWord ^ 0x36363636);
            }
            var innerHash = _hashWords(iKeyPad.concat(messageWords), 512 + messageBits);
            return _hashWords(oKeyPad.concat(innerHash, 0x80000000), 768);
        }

        function _hashWords(words, bits) {
            words.concat([0, 0]);
            while (words.length % 16) words.push(0);
            words[words.length - 2] = (Math.floor(bits / 0x100000000));
            words[words.length - 1] = (bits >>> 0);
            var a = 0x6a09e667;
            var b = 0xbb67ae85;
            var c = 0x3c6ef372;
            var d = 0xa54ff53a;
            var e = 0x510e527f;
            var f = 0x9b05688c;
            var g = 0x1f83d9ab;
            var h = 0x5be0cd19;
            var chunks = [];
            var i;
            for (i = 0; i < words.length; i += 16) {
                chunks.push(words.slice(i, i + 16));
            }
            var chunksLength = words.length / 16;
            for (var chunkIndex = 0; chunkIndex < chunksLength; chunkIndex++) {
                var chunk = chunks[chunkIndex];
                for (i = 16; i < 64; i++) {
                    var w0 = chunk[i - 15] >>> 0;
                    var s0 = (w0 >>> 7 | w0 << 25) ^ (w0 >>> 18 | w0 << 14) ^ (w0 >>> 3);
                    var w1 = chunk[i - 2] >>> 0;
                    var s1 = (w1 >>> 17 | w1 << 15) ^ (w1 >>> 19 | w1 << 13) ^ (w1 >>> 10);
                    chunk[i] = chunk[i - 16] + s0 + chunk[i - 7] + s1;
                }
                var ai = a >>> 0;
                var bi = b >>> 0;
                var ci = c >>> 0;
                var di = d >>> 0;
                var ei = e >>> 0;
                var fi = f >>> 0;
                var gi = g >>> 0;
                var hi = h >>> 0;
                for (i = 0; i < 64; i++) {
                    var S0 = (ai >>> 2 | ai << 30) ^ (ai >>> 13 | ai << 19) ^ (ai >>> 22 | ai << 10);
                    var maj = (ai & bi) ^ (ai & ci) ^ (bi & ci);
                    var t2 = (S0 + maj);
                    var S1 = (ei >>> 6 | ei << 26) ^ (ei >>> 11 | ei << 21) ^ (ei >>> 25 | ei << 7);
                    var ch = (ei & fi) ^ (~ei & gi);
                    var t1 = (hi + S1 + ch + _K[i] + chunk[i]);
                    hi = gi;
                    gi = fi;
                    fi = ei;
                    // BREADCRUMB
                    ei = (di + t1) >>> 0;
                    di = ci;
                    ci = bi;
                    bi = ai;
                    ai = (t1 + t2) >>> 0;
                }
                a = (a + ai);
                b = (b + bi);
                c = (c + ci);
                d = (d + di);
                e = (e + ei);
                f = (f + fi);
                g = (g + gi);
                h = (h + hi);
            }
            return [a >>> 0, b >>> 0, c >>> 0, d >>> 0, e >>> 0, f >>> 0, g >>> 0, h >>> 0];
        }

        function _charStringToWords(charString) {
            while (charString.length % 4) charString += "\x00";
            var words = [];
            for (var i = 0; i < charString.length; i += 4) {
                words.push(charString.charCodeAt(i) << 24 | charString.charCodeAt(i + 1) << 16 | charString.charCodeAt(i + 2) << 8 | charString.charCodeAt(i + 3));
            }
            return words;
        }

        return crytoped;

    });
})(typeof define == 'function' && define.amd ? define : function (factory) {
        module.exports = factory();
    });