mod sha2;
mod sha1;

use crate::utils::UsizeCast;
use crate::hash::sha2::SHA256;
use crate::hash::sha2::SHA224;
use crate::hash::sha2::SHA512;
use crate::hash::sha2::SHA384;
use crate::hash::sha2::SHA2_STATE_SIZE;
use crate::hash::sha2::SHA256_BLOCKSIZE;
use crate::hash::sha2::SHA512_BLOCKSIZE;
use crate::hash::sha1::SHA1;
use crate::hash::sha1::SHA1_STATE_SIZE;
use crate::hash::sha1::SHA1_BLOCKSIZE;
use num::traits::WrappingAdd;
use num::Zero;
use num_traits::PrimInt;
use core::ops::BitAnd;
use core::ops::BitXor;
use core::ops::BitOrAssign;
use core::ops::Not;
use core::convert::From;
use core::mem::size_of;

enum Error {
    Err,
}

enum Success {
    OK,
    Again,
}

#[derive(Debug)]
pub struct HashDataCtx<const BLOCKSIZE: usize, const STATE_SIZE: usize, S> {
    count: u64,
    buffer: [u8; BLOCKSIZE],
    rem_pos: usize,
    state: [S; STATE_SIZE],
}

trait Operations<
    const BLOCKSIZE: usize,
    const DIGEST_SIZE: usize,
    const STATE_SIZE: usize,
    T: PrimInt + BitAnd<Output=T> + Not<Output=T> + BitXor<Output=T> +
        Zero + WrappingAdd + Copy + BitOrAssign + From<u8>> {

    fn _transform(&self, state: &mut [T; STATE_SIZE], input: &[u8]);
    
    fn _init(&self, ctx: &mut HashDataCtx<BLOCKSIZE, STATE_SIZE, T>);

    fn Ttou8(x:T) -> u8;

    fn _update(&self, ctx: &mut HashDataCtx<BLOCKSIZE, STATE_SIZE, T>, input: &[u8]) {
        self._process(ctx, input);
    }

    fn _finish(
        &self,
        ctx: &mut HashDataCtx<BLOCKSIZE, STATE_SIZE, T>,
        output: &mut [u8],
    ) {
        /* Apply padding to last block and proccess it. */
        match Self::_padding(&mut ctx.buffer, ctx.count, true) {
            Ok(Success::Again) => {
                self._transform(&mut ctx.state, &ctx.buffer);
                ctx.buffer.fill(0);
                Self::_padding(&mut ctx.buffer, ctx.count, false);
            }
            _ => (),
        }
        self._transform(&mut ctx.state, &ctx.buffer);

        /* Truncate output if needed */
        let mut digest_size = output.len();
        digest_size = if digest_size > DIGEST_SIZE {
            DIGEST_SIZE
        } else {
            digest_size
        };

        /* Last step. */
        let mut j = 0;
        for i in 0..digest_size {
            output[i] = Self::Ttou8(ctx.state[j / size_of::<T>()] >> (((size_of::<T>() - 1) * 8) - (i % size_of::<T>() * 8))) & 0xFF;
            j += 1;
        }
    }

    fn _process(
        &self,
        ctx: &mut HashDataCtx<BLOCKSIZE, STATE_SIZE, T>,
        mut input: &[u8],
    ) -> Result<(), Error> {
        if input.len() == 0 {
            return Ok(());
        }

        let mut insize = input.len();
        ctx.count += insize as u64;

        // Remainder buffer is not empty and can be filled up to a full block.
        if ctx.rem_pos > 0 && (ctx.rem_pos + insize) >= BLOCKSIZE {
            // Fill buffer with input and process it.
            ctx.buffer[ctx.rem_pos..].copy_from_slice(&input[..BLOCKSIZE - ctx.rem_pos]);
            self._transform(&mut ctx.state, &ctx.buffer);

            // Adjust input ref and size by the amount of bytes used to fill up the buffer
            input = &input[BLOCKSIZE - ctx.rem_pos..];
            insize -= BLOCKSIZE - ctx.rem_pos;
            ctx.rem_pos = 0;
            ctx.buffer.fill(0);

        // Not enough input for full blocks. Copy to buffer.
        } else if (ctx.rem_pos + insize) < BLOCKSIZE {
            ctx.buffer[ctx.rem_pos..ctx.rem_pos + insize].copy_from_slice(&input);
            ctx.rem_pos += insize;
            return Ok(());
        }

        let nblocks = insize / BLOCKSIZE;

        // Process available blocks.
        self._transform(&mut ctx.state, input);

        // Copy residual bytes to buffer.
        if insize % BLOCKSIZE != 0 {
            ctx.rem_pos = insize - (nblocks * BLOCKSIZE);
            ctx.buffer[..ctx.rem_pos]
                .copy_from_slice(&input[nblocks * BLOCKSIZE..]);
        }

        return Ok(());
    }

    fn _padding(msg: &mut [u8], msgsize: u64, is_fst_call: bool) -> Result<Success, Error> {
        let lbits: u64;
        /* Compute number of bits and return with an error if result overflows. */
        if let Some(v) = msgsize.checked_mul(8) {
            lbits = v;
        } else {
            return Err(Error::Err);
        }

        if is_fst_call {
            /* Set next byte to 10000000 */
            msg[msgsize as usize % BLOCKSIZE] = 128;
            let mut i = (msgsize as usize % BLOCKSIZE) as usize + 1;

            /* Do we have enough splace to append a blocksize bits block with the
             * encoding of the message length? */
            if ((BLOCKSIZE - (msgsize as usize % BLOCKSIZE)) * 8 > BLOCKSIZE) && is_fst_call {
                /* Note:
                 *  _Theoretically_ there should be a distinciton here based on the blocksize.
                 *  According to the RFC the padding scheme of SHA256 expresses the length
                 *  of the message as a 64bit int, whereas SHA512 even uses a 128bit int.
                 *  I've opted to not make that distinction since I'm not planning to
                 *  hash messages ~ 2'091'752 terabytes. If that's what you've intended
                 *  to do:
                 *
                 *  			Bruh, WTF?!!! o.O
                 */

                /* Zeros.....*/
                msg[i..BLOCKSIZE - 8].fill(0);

                i += (BLOCKSIZE - 8 - i);

                msg[i] = (lbits >> 56) as u8 & 0xFF;
                msg[i + 1] = (lbits >> 48) as u8 & 0xFF;
                msg[i + 2] = (lbits >> 40) as u8 & 0xFF;
                msg[i + 3] = (lbits >> 32) as u8 & 0xFF;
                msg[i + 4] = (lbits >> 24) as u8 & 0xFF;
                msg[i + 5] = (lbits >> 16) as u8 & 0xFF;
                msg[i + 6] = (lbits >> 8) as u8 & 0xFF;
                msg[i + 7] = lbits as u8 & 0xFF;

                return Ok(Success::OK);
            }
            /* We have to write the length into a subsequent block. */
            else {
                msg[i..BLOCKSIZE].fill(0);

                return Ok(Success::Again);
            }
        } else {
            if BLOCKSIZE == 64 {
                msg[BLOCKSIZE - 4] = (lbits >> 24) as u8 & 0xFF;
                msg[BLOCKSIZE - 3] = (lbits >> 16) as u8 & 0xFF;
                msg[BLOCKSIZE - 2] = (lbits >> 8) as u8 & 0xFF;
                msg[BLOCKSIZE - 1] = (lbits & 0xFF) as u8;
            } else if BLOCKSIZE == 128 {
                msg[BLOCKSIZE - 8] = (lbits >> 56) as u8 & 0xFF;
                msg[BLOCKSIZE - 7] = (lbits >> 48) as u8 & 0xFF;
                msg[BLOCKSIZE - 6] = (lbits >> 40) as u8 & 0xFF;
                msg[BLOCKSIZE - 5] = (lbits >> 32) as u8 & 0xFF;
                msg[BLOCKSIZE - 4] = (lbits >> 24) as u8 & 0xFF;
                msg[BLOCKSIZE - 3] = (lbits >> 16) as u8 & 0xFF;
                msg[BLOCKSIZE - 2] = (lbits >> 8) as u8 & 0xFF;
                msg[BLOCKSIZE - 1] = (lbits & 0xFF) as u8;
            } else {
                return Err(Error::Err);
            }

            return Ok(Success::OK);
        }
    }
}

#[derive(Debug)]
pub enum SHA {
    SHA1Ctx {
        data: HashDataCtx<SHA1_BLOCKSIZE, SHA1_STATE_SIZE, u32>,
        ops: SHA1,
    },
    SHA256Ctx {
        data: HashDataCtx<SHA256_BLOCKSIZE, SHA2_STATE_SIZE, u32>,
        ops: SHA256,
    },
    SHA224Ctx {
        data: HashDataCtx<SHA256_BLOCKSIZE, SHA2_STATE_SIZE, u32>,
        ops: SHA224,
    },
    SHA512Ctx {
        data: HashDataCtx<SHA512_BLOCKSIZE, SHA2_STATE_SIZE, u64>,
        ops: SHA512,
    },
    SHA384Ctx {
        data: HashDataCtx<SHA512_BLOCKSIZE, SHA2_STATE_SIZE, u64>,
        ops: SHA384,
    }
}

impl SHA {
    pub fn new_sha1() -> Self {
        return SHA::SHA1Ctx {
            data: HashDataCtx {
                count: 0,
                buffer: [0; SHA1_BLOCKSIZE],
                rem_pos: 0,
                state: [0; SHA1_STATE_SIZE],
            },
            ops: SHA1,
        };
    }
    pub fn new_sha256() -> Self {
        return SHA::SHA256Ctx {
            data: HashDataCtx {
                count: 0,
                buffer: [0; SHA256_BLOCKSIZE],
                rem_pos: 0,
                state: [0; SHA2_STATE_SIZE],
            },
            ops: SHA256,
        };
    }

    pub fn new_sha224() -> Self {
        return SHA::SHA224Ctx {
            data: HashDataCtx {
                count: 0,
                buffer: [0; SHA256_BLOCKSIZE],
                rem_pos: 0,
                state: [0; SHA2_STATE_SIZE],
            },
            ops: SHA224,
        };
    }
    
    pub fn new_sha384() -> Self {
        return SHA::SHA384Ctx {
            data: HashDataCtx {
                count: 0,
                buffer: [0; SHA512_BLOCKSIZE],
                rem_pos: 0,
                state: [0; SHA2_STATE_SIZE],
            },
            ops: SHA384,
        };
    }

    pub fn new_sha512() -> Self {
        return SHA::SHA512Ctx {
            data: HashDataCtx {
                count: 0,
                buffer: [0; SHA512_BLOCKSIZE],
                rem_pos: 0,
                state: [0; SHA2_STATE_SIZE],
            },
            ops: SHA512,
        };
    }

    pub fn init(&mut self) {
        match *self {
            SHA::SHA1Ctx{ref mut data, ref ops} => ops._init(data),
            SHA::SHA256Ctx{ref mut data, ref ops} => ops._init(data),
            SHA::SHA224Ctx{ref mut data, ref ops} => ops._init(data),
            SHA::SHA384Ctx{ref mut data, ref ops} => ops._init(data),
            SHA::SHA512Ctx{ref mut data, ref ops} => ops._init(data)
        }
    }

    pub fn update(&mut self, input: &[u8]) {
        match *self {
            SHA::SHA1Ctx{ref mut data, ref ops} => ops._update(data, input),
            SHA::SHA256Ctx{ref mut data, ref ops} => ops._update(data, input),
            SHA::SHA224Ctx{ref mut data, ref ops} => ops._update(data, input),
            SHA::SHA384Ctx{ref mut data, ref ops} => ops._update(data, input),
            SHA::SHA512Ctx{ref mut data, ref ops} => ops._update(data, input)
        }
    }

    pub fn finish(&mut self, output: &mut [u8]) {
        match *self {
            SHA::SHA1Ctx{ref mut data, ref ops} => ops._finish(data, output),
            SHA::SHA256Ctx{ref mut data, ref ops} => ops._finish(data, output),
            SHA::SHA224Ctx{ref mut data, ref ops} => ops._finish(data, output),
            SHA::SHA384Ctx{ref mut data, ref ops} => ops._finish(data, output),
            SHA::SHA512Ctx{ref mut data, ref ops} => ops._finish(data, output)
        }
    }
}
