import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import sys

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 %s <x_file> <y_file>" % sys.argv[0])
        return 1

    x_file = sys.argv[1]
    y_file = sys.argv[2]

    plot(x_file, y_file)

    return 0

def plot(x_f, y_f):
    with open(x_f) as f:
        x = f.readlines()
    with open(y_f) as f:
        y = f.readlines()

    x = np.array([int(e.strip()) for e in x])
    y = np.array([float(e.strip()) for e in y])
    print(x)
    print(y)

    plt.figure(figsize=(5,3))
    ax = plt.subplot(1, 1, 1)
    ax.plot(x, y, marker='+', color='b', label='<0.0001% Packet Loss')
    ax.legend(loc='upper left', ncol=1, fontsize=8)
    ax.set_xlabel('Number of cores')
    ax.set_ylabel('Mpps')
    ax.set_xlim(xmin=0.5, xmax=5.5)
    ax.set_ylim(ymin=0.0, ymax=25.0)
    # sometimes gotta muck with adjusting to maximize space
    plt.subplots_adjust(left=0.12, right=0.95, bottom=0.15, top=0.95)
    plt.savefig('graph.png', layout='tight', dpi=400)


if __name__ == "__main__":
    main()
