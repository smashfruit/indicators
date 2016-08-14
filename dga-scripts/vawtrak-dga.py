import sys


def PRNG(seed):
	seed = (seed * 0x41c64e6d) + 0x3039
	return (seed & 0xFFFFFFFF)

seed_mask = 0x7FFFFFFF

#seed - 0034b0d8
def main():
    init_seed = int(sys.argv[1],16)
    for j in range(0x96):
        seed = PRNG(init_seed)
        tmp = (seed & seed_mask) / 5
        rem = (seed & seed_mask) % 5
        rem += 7
    
        out = ""
        for i in range(rem):
            seed = PRNG(seed)
            tmp = (seed & seed_mask) % 0x1a
            out += chr(tmp + 0x61)
        print(out+'.ru')
        init_seed = seed
    

if __name__ == "__main__":
    main()
