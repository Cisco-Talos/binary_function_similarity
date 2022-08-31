#define WORD_SIZE 32      	// 32 bits
#define MAX_WORD 0xffffffff     // Maximum size of a dword.
#define BYTE_SIZE 8             // Amount of bits in a byte.

#define NUM_ITERS 4             // Amount of iterations per permutation.

// There are 128 RAND_DWORDS. Don't change the amount of random dwords here.

unsigned int RAND_DWORDS[] = {1445200656, 3877429363, 1060188777, 4260769784, 1438562000, 2836098482, 1986405151, 4230168452, 380326093, 2859127666, 1134102609, 788546250, 3705417527, 1779868252, 1958737986, 4046915967, 1614805928, 4160312724, 3682325739, 534901034, 2287240917, 2677201636, 71025852, 1171752314, 47956297, 2265969327, 2865804126, 1364027301, 2267528752, 1998395705, 576397983, 636085149, 3876141063, 1131266725, 3949079092, 1674557074, 2566739348, 3782985982, 2164386649, 550438955, 2491039847, 2409394861, 3757073140, 3509849961, 3972853470, 1377009785, 2164834118, 820549672, 2867309379, 1454756115, 94270429, 2974978638, 2915205038, 1887247447, 3641720023, 4292314015, 702694146, 1808155309, 95993403, 1529688311, 2883286160, 1410658736, 3225014055, 1903093988, 2049895643, 476880516, 3241604078, 3709326844, 2531992854, 265580822, 2920230147, 4294230868, 408106067, 3683123785, 1782150222, 3876124798, 3400886112, 1837386661, 664033147, 3948403539, 3572529266, 4084780068, 691101764, 1191456665, 3559651142, 709364116, 3999544719, 189208547, 3851247656, 69124994, 1685591380, 1312437435, 2316872331, 1466758250, 1979107610, 2611873442, 80372344, 1251839752, 2716578101, 176193185, 2142192370, 1179562050, 1290470544, 1957198791, 1435943450, 2989992875, 3703466909, 1302678442, 3343948619, 3762772165, 1438266632, 1761719790, 3668101852, 1283600006, 671544087, 1665876818, 3645433092, 3760380605, 3802664867, 1635015896, 1060356828, 1666255066, 2953295653, 2827859377, 386702151, 3372348076, 4248620909, 2259505262};


// Amount of rand dwords - 1:
#define NUM_DWORDS_MASK 0x7f

unsigned int ror(unsigned int x, unsigned int i) {
    // Rotate right a dword x by i bits.
    return (x >> i) | (x << (WORD_SIZE - i));
}


unsigned int perm(unsigned int num, unsigned int x) {
    // Permutation from dword to dword.
    // num is the permutation number. x is the input.
    unsigned int ror_index;
    for(unsigned int i=0; i<NUM_ITERS; ++i) {
        // Addition:
        x += RAND_DWORDS[(i + num + x) & NUM_DWORDS_MASK];
        // Rotation:
        ror_index = (x ^ RAND_DWORDS[(i + num + 1) & NUM_DWORDS_MASK]) & 0x1f;
        x = ror(x,ror_index);
        // Xor:
        x ^= RAND_DWORDS[(i + num + x) & NUM_DWORDS_MASK];
        // Rotation:
        ror_index = (x ^ RAND_DWORDS[(i + num + 1) & NUM_DWORDS_MASK]) & 0x1f;
        x = ror(x,ror_index);
    }
    return x;
}

int sign(
    unsigned char* data,
    unsigned int len,
    unsigned int *result,
    unsigned int num_perms) {

    // Find entry number <num> of the signature of data.
    // len is the length of the data.
    // The result is inside <result>, as an array of dwords.

    // We need at least 4 bytes to generate a signature.
    // We return -1 (error) if we don't have at least 4 bytes.
    if(len < 4) {
        return -1;
    }
    unsigned int y; // Current integer value of 4 consecutive bytes.
    unsigned int py; // Permutation over y.
    unsigned int min_py; // Minimum py ever found.

    for(unsigned int permi=0; permi<num_perms; ++permi) {
        // Initialize y to be the first dword from the data:
        y = (unsigned int)data[0] << 24;
        y += ((unsigned int)data[1]) << 16;
        y += ((unsigned int)data[2]) << 8;
        y += (unsigned int)data[3];

        // Calculate first permutation:
        py = perm(permi,y);
        min_py = py;

        for(unsigned int i=4; i<len; ++i) {
            y <<= 8;
            y += data[i];
            py = perm(permi,y);
            if(min_py > py) {
                min_py = py;
            }
        }
        // Save minimum perm value found to memory:
        result[permi] = min_py;
    }
    // Everything went well.
    // Result should be stored at <result>
    return 0;
}

