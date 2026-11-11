import { createCipheriv, createHash, createHmac, randomBytes } from 'crypto';

// Mail2Chat: Baileys has decryptPollVote but no encryptPollVote, so NOWEB could not vote on a poll. This is the same derivation as decryptPollVote
// (Baileys Utils/process-message.js) and as whatsmeow's EncryptPollVote, run the other way.

export interface PollVoteContext {
  /** The JID of whoever created the poll, in the form the poll arrived with (a LID or a phone-number JID). */
  pollCreatorJid: string;
  /** The id of the poll creation message. */
  pollMsgId: string;
  /** The poll's `messageContextInfo.messageSecret`. */
  pollEncKey: Uint8Array;
  /** Our own JID, in the same family (LID or phone number) as the creator's. */
  voterJid: string;
}

/** WhatsApp identifies a chosen option by the SHA-256 of its name. */
export function hashPollOption(name: string): Buffer {
  return createHash('sha256').update(Buffer.from(name)).digest();
}

/**
 * The protobuf PollVoteMessage: `repeated bytes selectedOptions = 1`, so each hash is the tag 0x0a, the length 0x20 and the 32 bytes. Written by hand so
 * that this file does not load Baileys (an ES module, which the unit tests cannot import).
 */
export function encodePollVoteMessage(optionNames: string[]): Buffer {
  const parts: Buffer[] = [];
  for (const name of optionNames) {
    parts.push(Buffer.from([0x0a, 0x20]), hashPollOption(name));
  }
  return Buffer.concat(parts);
}

/** Encrypts a vote for the options with these names. `iv` is only for tests; a real vote uses a fresh random one. */
export function encryptPollVote(
  optionNames: string[],
  ctx: PollVoteContext,
  iv: Buffer = randomBytes(12),
): { encPayload: Buffer; encIv: Buffer } {
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
  const encKey = createHmac('sha256', key0).update(sign).digest();
  const aad = Buffer.from(`${ctx.pollMsgId}\u0000${ctx.voterJid}`);

  const plaintext = encodePollVoteMessage(optionNames);
  const cipher = createCipheriv('aes-256-gcm', encKey, iv);
  cipher.setAAD(aad);
  const encPayload = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  return { encPayload: encPayload, encIv: iv };
}
