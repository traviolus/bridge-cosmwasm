use num::{BigInt, ToPrimitive, bigint::Sign::Plus};
use num::traits::Zero;
use std::str::FromStr;
use hex::{decode};

fn modulus(a: &BigInt, b: &BigInt) -> BigInt {
    ((a % b) + b) % b
}

fn inv_mod(a: BigInt, n: &BigInt) -> BigInt {
    return BigInt::modpow(&a, &(n.clone() - BigInt::from(2u8)), n);
}

fn ecc_add(a: &(BigInt, BigInt), b: &(BigInt, BigInt)) -> (BigInt, BigInt) {
    let _p: BigInt = BigInt::from_str("115792089237316195423570985008687907853269984665640564039457584007908834671663").unwrap();
    let l = modulus(&((&b.1 - &a.1) * inv_mod(&b.0 - &a.0, &_p)), &_p);
    let x = modulus(&(&l * &l - &a.0 - &b.0), &_p);
    let y = modulus(&(&l * (&a.0 - &x) - &a.1), &_p);
    return (x, y);
}

fn ecc_double(a: &(BigInt, BigInt)) -> (BigInt, BigInt) {
    let _p: BigInt = BigInt::from_str("115792089237316195423570985008687907853269984665640564039457584007908834671663").unwrap();
    let _a: BigInt = BigInt::from(0i8);
    let l = modulus(&((BigInt::from(3i8) * &a.0 * &a.0 + &_a) * inv_mod(BigInt::from(2i8) * &a.1, &_p)), &_p);
    let x = modulus(&(&l * &l - BigInt::from(2i8) * &a.0), &_p);
    let y = modulus(&(&l * (&a.0 - &x) - &a.1), &_p);
    return (x, y);
}

fn ecc_mul(point: (BigInt, BigInt), scalar: BigInt) -> (BigInt, BigInt) {
    let _p: BigInt = BigInt::from_str("115792089237316195423570985008687907853269984665640564039457584007908834671663").unwrap();
    if scalar == BigInt::from(0i8) || scalar >= _p {
        panic!("INVALID_SCALAR_OR_PRIVATEKEY");
    }
    let scalar_bin = &scalar.to_str_radix(2u32);
    let mut q = point.clone();
    for i in 1usize..scalar_bin.len() {
        q = ecc_double(&q);
        if scalar_bin.chars().nth(i).unwrap() == '1' {
            q = ecc_add(&q, &point)
        }
    }
    return q;
}

fn to_base(n: BigInt, b: BigInt) -> Vec<BigInt> {
    if n < BigInt::from(2i8) {
        return vec![n];
    }
    let mut temp = n.clone();
    let mut ans = Vec::new();
    while temp != BigInt::from(0i8) {
        ans = [vec![modulus(&temp, &b)], ans].concat();
        temp /= &b;
    }
    return ans;
}

fn ecc_sqrt(a: BigInt, p: BigInt) -> (BigInt, BigInt) {
    let mut n = a.clone();
    n = modulus(&n, &p);
    if n == BigInt::from(0i8) || n == BigInt::from(1i8) {
        return (n.clone(), modulus(&-&n, &p));
    }
    let phi = &p - BigInt::from(1i8);
    if BigInt::modpow(&n, &(&phi/BigInt::from(2i8)), &p) != BigInt::from(1i8) {
        return (BigInt::zero(), BigInt::zero());
    }
    if modulus(&p, &BigInt::from(4i8)) == BigInt::from(3i8) {
        let ans = BigInt::modpow(&n, &((&p + BigInt::from(1i8)) / BigInt::from(4i8)), &p);
        return (ans.clone(), modulus(&-&ans, &p));
    }
    let mut aa = BigInt::zero();
    for i in 1..p.to_i32().unwrap() {
        let temp = BigInt::modpow(&(modulus(&(&i * &i - &n), &p)), &(&phi / BigInt::from(2i8)), &p);
        if temp == phi {
            aa = BigInt::from(i);
            break
        }
    }
    let exponent = to_base((&p + 1) / 2, BigInt::from(2i8));

    fn cipolla_mult(ab: &(BigInt, BigInt), cd: &(BigInt, BigInt), w: BigInt, p: &BigInt) -> (BigInt, BigInt) {
        let (a, b) = ab;
        let (c, d) = cd;
        return (modulus(&(a * c + b * d * &w), &p), modulus(&(a * d + b * c), &p));
    }

    let mut x1 = (aa.clone(), BigInt::from(1i8));
    let mut x2 = cipolla_mult(&x1, &x1, &aa * &aa - &n, &p);
    for i in 1usize..exponent.len() {
        if exponent[i] == BigInt::zero() {
            x2 = cipolla_mult(&x2, &x1, &aa * &aa - &n, &p);
            x1 = cipolla_mult(&x1, &x1, &aa * &aa - &n, &p);
        } else {
            x1 = cipolla_mult(&x1, &x2, &aa * &aa - &n, &p);
            x2 = cipolla_mult(&x2, &x2, &aa * &aa - &n, &p);
        }
    }

    return (x1.clone().0, modulus(&-(&x1.0), &p));
}

pub fn ecrecover(_e: Vec<u8>, _r: Vec<u8>, _s: Vec<u8>, v: u8) -> Vec<u8> {
    if _e.len() != 32usize {
        panic!("size of message hash must be 32");
    }
    if _r.len() != 32usize {
        panic!("size of r must be 32");
    }
    if _s.len() != 32usize {
        panic!("size of s must be 32");
    }

    let _p: BigInt = BigInt::from_str("115792089237316195423570985008687907853269984665640564039457584007908834671663").unwrap();
    let _n: BigInt = BigInt::from_str("115792089237316195423570985008687907852837564279074904382605163141518161494337").unwrap();
    let _a: BigInt = BigInt::from_str("0").unwrap();
    let _b: BigInt = BigInt::from_str("7").unwrap();
    let _gx: BigInt = BigInt::from_bytes_be(Plus, decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap().as_slice());
    let _gy: BigInt = BigInt::from_bytes_be(Plus, decode("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8").unwrap().as_slice());
    let _g: (BigInt, BigInt) = (_gx, _gy);

    let e = BigInt::from_bytes_be(Plus, _e.as_slice());
    let r = BigInt::from_bytes_be(Plus, _r.as_slice());
    let s = BigInt::from_bytes_be(Plus, _s.as_slice());

    let x = modulus(&r, &_n);
    let mut y = &BigInt::default();
    let (y1, y2) = ecc_sqrt(&x * &x * &x + &x * &_a + &_b, _p);
    if v == 27u8 {
        y = if modulus(&y1, &BigInt::from(2i8)) == BigInt::from(0i8) { &y1 } else { &y2 };
    } else if v == 28u8 {
        y = if modulus(&y1, &BigInt::from(2i8)) == BigInt::from(1i8) { &y1 } else { &y2 };
    } else {
        panic!("ECRECOVER_ERROR: v must be 27 or 28");
    }

    let r_case = (x.clone(), modulus(&y, &_n));
    let x_inv = inv_mod(x.clone(), &_n);
    let gxh = ecc_mul(_g, modulus(&-&e, &_n));

    let pubkey = ecc_mul(ecc_add(&gxh, &ecc_mul(r_case, s)), x_inv);

    return decode([&format!("{:#064x}", pubkey.0)[2..], &format!("{:#064x}", pubkey.1)[2..]].concat()).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Sha256, Digest};
    use sha3::Keccak256;
    use hex::encode;

    #[test]
    fn modulus_test() {
        assert_eq!(modulus(&BigInt::from(-4i8), &BigInt::from(7i8)), BigInt::from(3i8));
    }

    #[test]
    fn inv_mod_test() {
        let a = BigInt::from_str("115792089237316195423570234324123").unwrap();
        let b = BigInt::from_str("4250").unwrap();
        assert_eq!(inv_mod(a, &b), BigInt::from(1531i32));
    }

    #[test]
    fn ecc_sqrt_test() {
        assert_eq!((BigInt::from(4i32), BigInt::from(3i32)), ecc_sqrt(BigInt::from(2i32), BigInt::from(7i32)));
        assert_eq!((BigInt::from(9872i32), BigInt::from(135i32)), ecc_sqrt(BigInt::from(8218i32), BigInt::from(10007i32)));
        assert_eq!((BigInt::from(37i32), BigInt::from(64i32)), ecc_sqrt(BigInt::from(56i32), BigInt::from(101i32)));
        assert_eq!((BigInt::from(1i32), BigInt::from(10i32)), ecc_sqrt(BigInt::from(1i32), BigInt::from(11i32)));
        assert_eq!((BigInt::from(0i32), BigInt::from(0i32)), ecc_sqrt(BigInt::from(8219i32), BigInt::from(10007i32)));
    }

    #[test]
    fn ecc_double_test() {
        assert_eq!(ecc_double(&(BigInt::from(1912u32), BigInt::from(223u32))), (BigInt::from_str("10494378455078205730540216562451615771374606786543908426186638201525773446469").unwrap(), BigInt::from_str("75906244361354189345714372194467376939603221449011543747977051595457551031006").unwrap()));
        assert_eq!(ecc_double(&(BigInt::from(1u8), BigInt::from(2u8))), (BigInt::from_str("65133050195990359925758679067386948167464366374422817272194891004448719502809").unwrap(), BigInt::from_str("66942301590323425479251975708147696727671709884823451085311415754572295044555").unwrap()));
    }

    #[test]
    fn ecc_add_test() {
        assert_eq!(ecc_add(&((BigInt::from(1912u32), BigInt::from(223u32))), &((BigInt::from(2142u32), BigInt::from(2425u32)))), (BigInt::from_str("110521250846324562180093500473698862822822458709594014356905337083692493006276").unwrap(), BigInt::from_str("92751833186513638337901668203372440942261438552731781653454281668646636798960").unwrap()));
    }

    #[test]
    fn ecrecover_test() {
        let r = decode("6916405D52FF02EC26DD78E831E0A179C89B99CBBDB15C9DA802B75A7621D5EB").unwrap();
        let s = decode("69CF40BE7AC1AA176B13BA4D57EB2B8735A5832014F0DC168EA6F580C51BB222").unwrap();
        let v = 28u8;
        let signed_data_prefix = decode("7808021184C002000000000022480A20").unwrap();
        let signed_data_suffix = decode("12240801122044551F853D916A7C630C0C210C921BAC7D05CE0C249DFC6088C0274F058418272A0C08DE9493850610F0FFAEEB02321362616E642D6C616F7A692D746573746E657431").unwrap();
        let block_hash = decode("8C36C3D12A378BD7E4E8F26BDECCA68B48390240DA456EE9C3292B6E36756AC4").unwrap();
        let mut hasher = Sha256::new();
        hasher.update([signed_data_prefix.as_slice(), block_hash.as_slice(), signed_data_suffix.as_slice()].concat());
        let hash_result = Vec::from(&hasher.finalize()[..]);

        let result = ecrecover(hash_result, r, s, v);
        let mut hasher = Keccak256::new();
        hasher.update(result.as_slice());
        let result = &hasher.finalize()[12..32];

        assert_eq!(result, decode("3b759C4d728e50D5cC04c75f596367829d5b5061").unwrap());
    }
}
