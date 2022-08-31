# The catalog1 sensitive hashing algorithm.
# By xorpd.

WORD_SIZE = 32      # 32 bits.
MAX_WORD = (1 << WORD_SIZE) - 1

BYTE_SIZE = 8       # 8 bits.
NUM_ITERS = 4

RAND_DWORDS = \
    [1445200656, 3877429363, 1060188777, 4260769784, 1438562000, 2836098482, 1986405151, 4230168452, 380326093, 2859127666, 1134102609, 788546250, 3705417527, 1779868252, 1958737986, 4046915967, 1614805928, 4160312724, 3682325739, 534901034, 2287240917, 2677201636, 71025852, 1171752314, 47956297, 2265969327, 2865804126, 1364027301, 2267528752, 1998395705, 576397983, 636085149, 3876141063, 1131266725, 3949079092, 1674557074, 2566739348, 3782985982, 2164386649, 550438955, 2491039847, 2409394861, 3757073140, 3509849961, 3972853470, 1377009785, 2164834118, 820549672, 2867309379, 1454756115, 94270429, 2974978638, 2915205038, 1887247447, 3641720023, 4292314015, 702694146, 1808155309, 95993403, 1529688311, 2883286160, 1410658736, 3225014055, 1903093988,
        2049895643, 476880516, 3241604078, 3709326844, 2531992854, 265580822, 2920230147, 4294230868, 408106067, 3683123785, 1782150222, 3876124798, 3400886112, 1837386661, 664033147, 3948403539, 3572529266, 4084780068, 691101764, 1191456665, 3559651142, 709364116, 3999544719, 189208547, 3851247656, 69124994, 1685591380, 1312437435, 2316872331, 1466758250, 1979107610, 2611873442, 80372344, 1251839752, 2716578101, 176193185, 2142192370, 1179562050, 1290470544, 1957198791, 1435943450, 2989992875, 3703466909, 1302678442, 3343948619, 3762772165, 1438266632, 1761719790, 3668101852, 1283600006, 671544087, 1665876818, 3645433092, 3760380605, 3802664867, 1635015896, 1060356828, 1666255066, 2953295653, 2827859377, 386702151, 3372348076, 4248620909, 2259505262]


def ror(x, i):
    """
    Rotate right x by i locations.
    x is a dword
    """
    # Make sure that i is in range:
    return ((x >> i) | (x << (WORD_SIZE - i))) & MAX_WORD


def perm(num, x):
    """
    A permutation from dwords to dwords.
    Implementation here is pretty arbitrary, and could be changed a bit if
    needed.
    num is the number of permutation (This could generate many different
    permutation functions)
    x is the input dword.
    """
    for i in range(NUM_ITERS):
        x += RAND_DWORDS[(i + num + x) % len(RAND_DWORDS)]
        x &= MAX_WORD
        ror_index = (x ^ RAND_DWORDS[(i + num + 1) % len(RAND_DWORDS)]) % \
            WORD_SIZE
        x = ror(x, ror_index)
        x ^= RAND_DWORDS[(i + num + x) % len(RAND_DWORDS)]
        ror_index = (x ^ RAND_DWORDS[(i + num + 1) % len(RAND_DWORDS)]) % \
            WORD_SIZE
        x = ror(x, ror_index)
        assert (x <= MAX_WORD) and (x >= 0)
    return x


def bytes_to_num(data):
    """
    Convert a string to a number
    """
    return int.from_bytes(bytes=data, byteorder='big')


def slow_sign(data, num_perms):
    """
    Sign over data.
    Use num_perms permutations. (The more you have, the more sensitive is the
    comparison later).
    """
    nbytes = WORD_SIZE // BYTE_SIZE
    if len(data) < nbytes:
        raise Exception('data must be at least of size {} bytes.'
                        .format(nbytes))

    res_sign = []

    for p in range(num_perms):
        num_iters = len(data) - nbytes + 1
        cur_sign = min([perm(p, bytes_to_num(data[i:i + nbytes])) for i in
                        range(num_iters)])
        res_sign.append(cur_sign)

    return res_sign
