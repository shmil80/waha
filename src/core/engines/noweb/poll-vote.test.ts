import {
  encryptPollVote,
  hashPollOption,
} from '@waha/core/engines/noweb/poll-vote';
import { createDecipheriv, createHash, createHmac, randomBytes } from 'crypto';

// The same steps as decryptPollVote of Baileys (Utils/process-message.js), written with node:crypto because jest cannot load Baileys (an ES module).
// Returns the selected hashes: the payload is a PollVoteMessage, `repeated bytes selectedOptions = 1`.
function decryptPollVote(
  vote: { encPayload: Buffer; encIv: Buffer },
  ctx: {
    pollCreatorJid: string;
    pollMsgId: string;
    pollEncKey: Uint8Array;
    voterJid: string;
  },
) {
  const sign = Buffer.concat([
    Buffer.from(ctx.pollMsgId),
    Buffer.from(ctx.pollCreatorJid),
    Buffer.from(ctx.voterJid),
    Buffer.from('Poll Vote'),
    Buffer.from([1]),
  ]);
  const key0 = createHmac('sha256', Buffer.alloc(32))
    .update(ctx.pollEncKey)
    .digest();
  const decKey = createHmac('sha256', key0).update(sign).digest();
  const aad = Buffer.from(`${ctx.pollMsgId}\u0000${ctx.voterJid}`);
  const body = vote.encPayload.subarray(0, vote.encPayload.length - 16);
  const tag = vote.encPayload.subarray(vote.encPayload.length - 16);
  const decipher = createDecipheriv('aes-256-gcm', decKey, vote.encIv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(body), decipher.final()]);
  const hashes: Buffer[] = [];
  for (let at = 0; at < plain.length; at += 34) {
    expect(plain[at]).toBe(0x0a);
    expect(plain[at + 1]).toBe(0x20);
    hashes.push(plain.subarray(at + 2, at + 34));
  }
  return { selectedOptions: hashes };
}

describe('encryptPollVote', () => {
  const ctx = {
    pollCreatorJid: '111111111111@s.whatsapp.net',
    pollMsgId: '3EB0AAAAAAAAAAAAAAAA',
    pollEncKey: randomBytes(32),
    voterJid: '222222222222@s.whatsapp.net',
  };

  it('is read back by the same steps as Baileys decryptPollVote', () => {
    const vote = encryptPollVote(['Yes', 'Maybe'], ctx);
    const decrypted = decryptPollVote(vote, ctx);
    expect(decrypted.selectedOptions).toEqual([
      hashPollOption('Yes'),
      hashPollOption('Maybe'),
    ]);
  });

  it('works with LID identities', () => {
    const lid = { ...ctx, pollCreatorJid: '333@lid', voterJid: '444@lid' };
    const vote = encryptPollVote(['No'], lid);
    expect(decryptPollVote(vote, lid).selectedOptions).toEqual([
      hashPollOption('No'),
    ]);
  });

  it('cannot be read with another voter', () => {
    const vote = encryptPollVote(['Yes'], ctx);
    expect(() =>
      decryptPollVote(vote, { ...ctx, voterJid: '999@s.whatsapp.net' }),
    ).toThrow();
  });

  it('uses a fresh iv each time', () => {
    const first = encryptPollVote(['Yes'], ctx);
    const second = encryptPollVote(['Yes'], ctx);
    expect(first.encIv.equals(second.encIv)).toBe(false);
  });

  it('hashes an option name with SHA-256', () => {
    const expected = createHash('sha256').update('Yes', 'utf8').digest();
    expect(hashPollOption('Yes').equals(expected)).toBe(true);
  });
});
