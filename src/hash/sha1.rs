use crate::hash::Operations;
use crate::hash::HashDataCtx;
use crate::utils::UsizeCast;

pub const SHA1_DIGEST_SIZE: usize = 20;
pub const SHA1_BLOCKSIZE: usize = 64;
pub const SHA1_STATE_SIZE: usize = 5;

#[derive(Debug)]
pub struct SHA1Ctx { pub data: HashDataCtx<SHA1_BLOCKSIZE, SHA1_STATE_SIZE, u32> }

impl Operations<SHA1_BLOCKSIZE, SHA1_DIGEST_SIZE, SHA1_STATE_SIZE, u32> for SHA1Ctx {

    fn Ttou8(x:u32) -> u8 {
        return x as u8;
    }

    fn _transform(state: &mut [u32; SHA1_STATE_SIZE], mut input: &[u8]) {

	    let mut a: u32;
        let mut b: u32;
        let mut c: u32;
        let mut d: u32;
        let mut e: u32;
        let mut T: u32;

	    let mut W: [u32;80] = [0;80];
        let mut mlen: i64 = input.len().i64() - SHA1_BLOCKSIZE.i64();
         
	    while mlen  >= 0 {
            mlen -= SHA1_BLOCKSIZE.i64();

	    	/* Set initial state */
	    	a = state[0];
	    	b = state[1];
	    	c = state[2];
	    	d = state[3];
	    	e = state[4];

	    	/* Compute schedule and intermediate values. */
	    	for t in 0..16 {
	    		W[t] =  u32::from(input[t * 4]) << 24; 
	    		W[t] |= u32::from(input[t * 4 + 1]) << 16; 
	    		W[t] |= u32::from(input[t * 4 + 2]) << 8; 
	    		W[t] |= u32::from(input[t * 4 + 3]); 

	    		T = (a.rotate_left(5).wrapping_add(sha1f(b, c, d, t)))
                    .wrapping_add(e)
                    .wrapping_add(W[t])
                    .wrapping_add(sha1k(t));
	    		e = d;
	    		d = c;
	    		c = b.rotate_left(30);
	    		b = a;
	    		a = T;
	    	}
	    	
	    	for t in 16..80 {
	    		W[t] = (W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]).rotate_left(1);

	    		T = a.rotate_left(5)
                    .wrapping_add(sha1f(b, c, d, t))
                    .wrapping_add(e)
                    .wrapping_add(W[t])
                    .wrapping_add(sha1k(t));
	    		e = d;
	    		d = c;
	    		c = b.rotate_left(30);
	    		b = a;
	    		a = T;
	    	}

	    	state[0] = state[0].wrapping_add(a);
	    	state[1] = state[1].wrapping_add(b);
	    	state[2] = state[2].wrapping_add(c);
	    	state[3] = state[3].wrapping_add(d);
	    	state[4] = state[4].wrapping_add(e);

            input = &input[SHA1_BLOCKSIZE..];
	    }
    }
    fn _init(ctx: &mut HashDataCtx<SHA1_BLOCKSIZE, SHA1_STATE_SIZE, u32>) {
        // clear ctx since it could be reused
        ctx.count = 0;
        ctx.rem_pos = 0;
        ctx.buffer.fill(0);
        
        // set initial state
	    ctx.state[0] = 0x67452301;
	    ctx.state[1] = 0xEFCDAB89;
	    ctx.state[2] = 0x98BADCFE;
	    ctx.state[3] = 0x10325476;
	    ctx.state[4] = 0xC3D2E1F0;
    }
}

fn sha1f(x: u32, y: u32, z: u32, t: usize) -> u32 {
        let mut res: u32 = 0;

        if 19 >= t{
            res = ((x & y) | ((!x) & z));
        } else if 20 <= t && 39 >= t {
            res = x ^ y ^ z;
        } else if 40 <= t && 59 >= t {
            res = (x & y) | ( x & z) | (y & z);
        } else if 60 <= t && 79 >= t {
            res = x ^ y ^ z;
        }

        return res;
}

fn sha1k(t :usize) -> u32 {
        let mut res: u32 = 0;

        if 19 >= t {
            res = 0x5A827999;
        }
        else if 20 <= t && 39 >= t {
            res = 0x6ED9EBA1;
        }
        else if 40 <= t && 59 >= t {
            res = 0x8F1BBCDC;
        }
        else if 60 <= t && 79 >= t {
            res = 0xCA62C1D6;
        }

        return res;
}
