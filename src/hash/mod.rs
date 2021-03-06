mod sha2;
mod sha1;

use crate::common::api::{StreamingAPI, DefaultInit, SingleInputUpdate, SingleOutputFinish};
use crate::utils::Cast;
use crate::hash::sha2::SHA256Ctx;
use crate::hash::sha2::SHA224Ctx;
use crate::hash::sha2::SHA512Ctx;
use crate::hash::sha2::SHA384Ctx;
use crate::hash::sha2::SHA2_STATE_SIZE;
use crate::hash::sha2::SHA256_BLOCKSIZE;
use crate::hash::sha2::SHA512_BLOCKSIZE;
use crate::hash::sha1::SHA1Ctx;
use crate::hash::sha1::SHA1_STATE_SIZE;
use crate::hash::sha1::SHA1_BLOCKSIZE;
use num::traits::WrappingAdd;
use num::Zero;
use num_traits::PrimInt;
use core::ops::BitAnd;
use core::ops::BitXor;
use core::ops::BitOrAssign;
use core::ops::Not;
use core::mem::size_of;
use crate::common::{Success, Error};


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
        Zero + WrappingAdd + Copy + BitOrAssign + Cast<u8>> {

    fn _transform(state: &mut [T; STATE_SIZE], input: &[u8]);

    fn _init(ctx: &mut HashDataCtx<BLOCKSIZE, STATE_SIZE, T>);

    fn _finish(
        ctx: &mut HashDataCtx<BLOCKSIZE, STATE_SIZE, T>,
        output: &mut [u8],
    ) -> Result<Success, Error> {
        /* Apply padding to last block and proccess it. */
        if let Success::Again = Self::_padding(&mut ctx.buffer, ctx.count, true)? {
                Self::_transform(&mut ctx.state, &ctx.buffer);
                ctx.buffer.fill(0);
                Self::_padding(&mut ctx.buffer, ctx.count, false);
        }

        Self::_transform(&mut ctx.state, &ctx.buffer);

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
            // Copy result from state array to output buffer.
            // T is a "wider" type than u8, so we have to shift and mask to get the proper result.
            output[i] = (ctx.state[j / size_of::<T>()] >> (((size_of::<T>() - 1) * 8) - (i % size_of::<T>() * 8))).cast() & 0xFF;
            j += 1;
        }

        return Ok(Success::OK);
    }

    fn _process(
        ctx: &mut HashDataCtx<BLOCKSIZE, STATE_SIZE, T>,
        mut input: &[u8],
    ) -> Result<Success, Error> {
        if input.len() == 0 {
            return Ok(Success::OK);
        }

        let mut insize = input.len();
        ctx.count += insize as u64;

        // Remainder buffer is not empty and can be filled up to a full block.
        if ctx.rem_pos > 0 && (ctx.rem_pos + insize) >= BLOCKSIZE {
            // Fill buffer with input and process it.
            ctx.buffer[ctx.rem_pos..].copy_from_slice(&input[..BLOCKSIZE - ctx.rem_pos]);
            Self::_transform(&mut ctx.state, &ctx.buffer);

            // Adjust input ref and size by the amount of bytes used to fill up the buffer
            input = &input[BLOCKSIZE - ctx.rem_pos..];
            insize -= BLOCKSIZE - ctx.rem_pos;
            ctx.rem_pos = 0;
            ctx.buffer.fill(0);

        // Not enough input for full blocks. Copy to buffer.
        } else if (ctx.rem_pos + insize) < BLOCKSIZE {
            ctx.buffer[ctx.rem_pos..ctx.rem_pos + insize].copy_from_slice(&input);
            ctx.rem_pos += insize;
            return Ok(Success::OK);
        }

        let nblocks = insize / BLOCKSIZE;

        // Process available blocks.
        Self::_transform(&mut ctx.state, input);

        // Copy residual bytes to buffer.
        if insize % BLOCKSIZE != 0 {
            ctx.rem_pos = insize - (nblocks * BLOCKSIZE);
            ctx.buffer[..ctx.rem_pos]
                .copy_from_slice(&input[nblocks * BLOCKSIZE..]);
        }

        return Ok(Success::OK);

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

                i += BLOCKSIZE - 8 - i;

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
    SHA1(SHA1Ctx),
    SHA256(SHA256Ctx),
    SHA224(SHA224Ctx),
    SHA512(SHA512Ctx),
    SHA384(SHA384Ctx),
}

impl SHA {
    pub fn new_sha1() -> Self {
        return SHA::SHA1(SHA1Ctx {
            data: HashDataCtx {
                count: 0,
                buffer: [0; SHA1_BLOCKSIZE],
                rem_pos: 0,
                state: [0; SHA1_STATE_SIZE],
            }
        });
    }
    pub fn new_sha256() -> Self {
        return SHA::SHA256(SHA256Ctx {
            data: HashDataCtx {
                count: 0,
                buffer: [0; SHA256_BLOCKSIZE],
                rem_pos: 0,
                state: [0; SHA2_STATE_SIZE],
            }
        });
    }

    pub fn new_sha224() -> Self {
        return SHA::SHA224(SHA224Ctx {
            data: HashDataCtx {
                count: 0,
                buffer: [0; SHA256_BLOCKSIZE],
                rem_pos: 0,
                state: [0; SHA2_STATE_SIZE],
            }
        });
    }

    pub fn new_sha384() -> Self {
        return SHA::SHA384(SHA384Ctx {
            data: HashDataCtx {
                count: 0,
                buffer: [0; SHA512_BLOCKSIZE],
                rem_pos: 0,
                state: [0; SHA2_STATE_SIZE],
            }
        });
    }

    pub fn new_sha512() -> Self {
        return SHA::SHA512(SHA512Ctx {
            data: HashDataCtx {
                count: 0,
                buffer: [0; SHA512_BLOCKSIZE],
                rem_pos: 0,
                state: [0; SHA2_STATE_SIZE],
            }
        });
    }
}


impl StreamingAPI for SHA {}

impl DefaultInit for SHA {
    fn init(&mut self) -> Result<Success, Error>{
        match &mut *self {
            SHA::SHA1(ctx)   => SHA1Ctx::_init(&mut ctx.data),
            SHA::SHA256(ctx) => SHA256Ctx::_init(&mut ctx.data),
            SHA::SHA224(ctx) => SHA224Ctx::_init(&mut ctx.data),
            SHA::SHA384(ctx) => SHA384Ctx::_init(&mut ctx.data),
            SHA::SHA512(ctx) => SHA512Ctx::_init(&mut ctx.data)
        }

        return Ok(Success::OK);
    }
}

impl SingleInputUpdate for SHA {
    fn update(&mut self, input: &[u8]) -> Result<Success, Error> {
        let ret = match &mut *self {
            SHA::SHA1(ctx)   => SHA1Ctx::_process(&mut ctx.data, input),
            SHA::SHA256(ctx) => SHA256Ctx::_process(&mut ctx.data, input),
            SHA::SHA224(ctx) => SHA224Ctx::_process(&mut ctx.data, input),
            SHA::SHA384(ctx) => SHA384Ctx::_process(&mut ctx.data, input),
            SHA::SHA512(ctx) => SHA512Ctx::_process(&mut ctx.data, input)
        };

        return ret;
    }
}

impl SingleOutputFinish for SHA {
    fn finish(&mut self, output: &mut [u8]) -> Result<Success, Error> {
        let ret = match &mut *self {
            SHA::SHA1(ctx)   => SHA1Ctx::_finish(&mut ctx.data, output),
            SHA::SHA256(ctx) => SHA256Ctx::_finish(&mut ctx.data, output),
            SHA::SHA224(ctx) => SHA224Ctx::_finish(&mut ctx.data, output),
            SHA::SHA384(ctx) => SHA384Ctx::_finish(&mut ctx.data, output),
            SHA::SHA512(ctx) => SHA512Ctx::_finish(&mut ctx.data, output)
        };

        return ret;
    }
}
