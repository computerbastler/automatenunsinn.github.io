"use strict";
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
Object.defineProperty(exports, "__esModule", { value: true });
var base32_encoding_1 = require("base32-encoding");
var xtea_1 = require("xtea");
var crc_1 = require("crc");
var Fsc = /** @class */ (function () {
    function Fsc() {
        this._date = null;
    }
    Object.defineProperty(Fsc.prototype, "RandomId", {
        get: function () {
            return this._randomId;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(Fsc.prototype, "HomologationId", {
        get: function () {
            return this._homologationId;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(Fsc.prototype, "ProgramId", {
        get: function () {
            return this._programId;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(Fsc.prototype, "Date", {
        get: function () {
            return this._date;
        },
        enumerable: false,
        configurable: true
    });
    Fsc.GenerateBauartKey = function (keyInd, masterKey) {
        var bauartKey = __spreadArray([], masterKey, true);
        if (keyInd !== 0) {
            for (var i = 0; i < 4; i++) {
                bauartKey[i] += keyInd + 21545;
                bauartKey[i] -= (~keyInd << 16) + 880279552;
            }
        }
        return bauartKey;
    };
    Fsc.prototype.SetKeyInd = function (keyInd) {
        var masterKey = [1878738899, 2928249263, 3927923331, 606835660];
        var bauartKey = Fsc.GenerateBauartKey(keyInd, masterKey);
        this.crypto = new xtea_1.default(Buffer.from(new Uint32Array(bauartKey).buffer));
    };
    Fsc.prototype.Decrypt = function (code, keyInd) {
        if (keyInd === void 0) { keyInd = 0; }
        var array1 = new Uint8Array(16);
        var array2 = new Uint8Array(16);
        var num1 = 0;
        for (var _i = 0, _a = Array.from((0, base32_encoding_1.decode)((0, base32_encoding_1.parse)(code))); _i < _a.length; _i++) {
            var num2 = _a[_i];
            if (num1 !== 16) {
                array1[num1++] = num2;
            }
            else {
                break;
            }
        }
        this.SetKeyInd(keyInd);
        var block1 = Buffer.from(array1.subarray(0, 8));
        var block2 = Buffer.from(array1.subarray(8, 16));
        this.crypto.decrypt(block1);
        this.crypto.decrypt(block2);
        array2.set(block1, 0);
        array2.set(block2, 8);
        var computedCrc = crc_1.default.crc8(array2.subarray(0, 15));
        if (computedCrc !== array2[15]) {
            throw new Error("Crc8 failure decoding key");
        }
        this._randomId = array2[0] | (array2[1] << 8);
        this._homologationId = (array2[2] | (array2[3] << 8) | (array2[4] << 16) | (array2[5] << 24)) >>> 0;
        this._programId = (array2[6] | (array2[7] << 8) | (array2[8] << 16) | (array2[9] << 24)) >>> 0;
        this._date = array2[11] === 0 || array2[12] === 0
            ? null
            : new Date(2000 + array2[10], array2[11] - 1, array2[12]);
        return array2;
    };
    Fsc.prototype.EncryptFsc = function (date) {
        var plaintext = new Uint8Array(16);
        plaintext.set(new Uint8Array(new Uint32Array([this._homologationId]).buffer), 0);
        plaintext.set(new Uint8Array(new Uint16Array([this._randomId]).buffer), 7);
        plaintext[4] = date.getFullYear() - 2000;
        plaintext[5] = date.getMonth() + 1;
        plaintext[6] = date.getDate();
        return this.Encrypt(plaintext, (this._homologationId >> 5) / 3125 & 0xffff);
    };
    Fsc.prototype.Encrypt = function (plaintext, keyInd) {
        var computedCrc = crc_1.default.crc8(plaintext.subarray(0, 15));
        plaintext[15] = computedCrc + 1;
        this.SetKeyInd(keyInd);
        var block1 = Buffer.from(plaintext.subarray(0, 8));
        var block2 = Buffer.from(plaintext.subarray(8, 16));
        this.crypto.encrypt(block1);
        this.crypto.encrypt(block2);
        var result = new Uint8Array(16);
        result.set(block1, 0);
        result.set(block2, 8);
        return (0, base32_encoding_1.stringify)((0, base32_encoding_1.encode)(result));
    };
    Fsc.prototype.CreateKc = function (homologationId, enableCode) {
        var array = new Uint8Array(8);
        array.set(new Uint8Array(new Uint32Array([homologationId]).buffer), 0);
        array.set(new Uint8Array(new Uint16Array([enableCode]).buffer), 4);
        var computedCrc = crc_1.default.crc8(array.subarray(0, 7));
        array[7] = computedCrc;
        this.SetKeyInd(4712);
        var block = Buffer.from(array);
        this.crypto.encrypt(block);
        return (0, base32_encoding_1.stringify)((0, base32_encoding_1.encode)(new Uint8Array(block)));
    };
    return Fsc;
}());
