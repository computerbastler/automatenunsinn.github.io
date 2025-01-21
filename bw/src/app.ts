import { encode as base32Encode, decode as base32Decode, stringify, parse } from 'base32-encoding';
import Xtea from 'xtea';
import crc from 'crc';

class Fsc {
  private _randomId: number;
  private _homologationId: number;
  private _programId: number;
  private _date: Date | null = null;
  private crypto: Xtea;

  get RandomId(): number {
    return this._randomId;
  }

  get HomologationId(): number {
    return this._homologationId;
  }

  get ProgramId(): number {
    return this._programId;
  }

  get Date(): Date | null {
    return this._date;
  }

  private static GenerateBauartKey(keyInd: number, masterKey: number[]): number[] {
    const bauartKey = [...masterKey];

    if (keyInd !== 0) {
      for (let i = 0; i < 4; i++) {
        bauartKey[i] += keyInd + 21545;
        bauartKey[i] -= (~keyInd << 16) + 880279552;
      }
    }

    return bauartKey;
  }

  private SetKeyInd(keyInd: number): void {
    const masterKey = [1878738899, 2928249263, 3927923331, 606835660];
    const bauartKey = Fsc.GenerateBauartKey(keyInd, masterKey);

    this.crypto = new Xtea(Buffer.from(new Uint32Array(bauartKey).buffer));
  }

  public Decrypt(code: string, keyInd: number = 0): Uint8Array {
    const array1 = new Uint8Array(16);
    const array2 = new Uint8Array(16);
  
    let num1 = 0;
    for (const num2 of Array.from(base32Decode(parse(code)))) {
      if (num1 !== 16) {
        array1[num1++] = num2;
      } else {
        break;
      }
    }
  
    this.SetKeyInd(keyInd);
  
    const block1 = Buffer.from(array1.subarray(0, 8));
    const block2 = Buffer.from(array1.subarray(8, 16));
  
    this.crypto.decrypt(block1);
    this.crypto.decrypt(block2);
  
    array2.set(block1, 0);
    array2.set(block2, 8);
  
    const computedCrc = crc.crc8(array2.subarray(0, 15));
  
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
  }

  public EncryptFsc(date: Date): string {
    const plaintext = new Uint8Array(16);
    plaintext.set(new Uint8Array(new Uint32Array([this._homologationId]).buffer), 0);
    plaintext.set(new Uint8Array(new Uint16Array([this._randomId]).buffer), 7);

    plaintext[4] = date.getFullYear() - 2000;
    plaintext[5] = date.getMonth() + 1;
    plaintext[6] = date.getDate();

    return this.Encrypt(plaintext, (this._homologationId >> 5) / 3125 & 0xffff);
  }

  public Encrypt(plaintext: Uint8Array, keyInd: number): string {
    const computedCrc = crc.crc8(plaintext.subarray(0, 15));
    plaintext[15] = computedCrc + 1;

    this.SetKeyInd(keyInd);

    const block1 = Buffer.from(plaintext.subarray(0, 8));
    const block2 = Buffer.from(plaintext.subarray(8, 16));

    this.crypto.encrypt(block1);
    this.crypto.encrypt(block2);

    const result = new Uint8Array(16);
    result.set(block1, 0);
    result.set(block2, 8);

    return stringify(base32Encode(result));
  }

  public CreateKc(homologationId: number, enableCode: number): string {
    const array = new Uint8Array(8);
    array.set(new Uint8Array(new Uint32Array([homologationId]).buffer), 0);
    array.set(new Uint8Array(new Uint16Array([enableCode]).buffer), 4);

    const computedCrc = crc.crc8(array.subarray(0, 7));
    array[7] = computedCrc;

    this.SetKeyInd(4712);

    const block = Buffer.from(array);

    this.crypto.encrypt(block);
    
    return stringify(base32Encode(new Uint8Array(block)));
  }
}
