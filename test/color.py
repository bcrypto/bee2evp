import color_console as cons
import sys

def test():
  cons.print_colored('error', cons.bcolors.FAIL)

if __name__ == "__main__":
	sys.stdout.write('error ')
	test()

