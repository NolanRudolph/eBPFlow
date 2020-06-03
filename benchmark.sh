#!/bin/bash

if [[ $# -ne 4 ]]; then
  printf "Usage: ./benchmark <IF> <time> <agg> <cpus>\n"
  printf "\tIF: Network interface\n"
  printf "\ttime: Net duration to run for (s)\n"
  printf "\tagg: Aggregation time (s)\n"
  printf "\tcores: # of cores to use (>1)\n"
  printf "\nExample:\n"
  printf "\t./benchmark eno1 20 5 3 \n"
  printf "\t-- Run on interface eno1 for 20s, aggregation period of 5s, using only 3 cpus.\n"
  exit 1;
fi

if [[ ! -f "./XDP/xdp_collect.py" ]]; then
  echo "Please call from the /path/to/eBPF-Flow-Collector home directory."
  exit 1;
fi

IF=$1
TIME=$2
AGG=$3
CPUS=$4
NCPUS=$(nproc)

if [[ 1 -eq $CPUS ]]; then
  echo "Please use more than 1 CPU."
  exit 1
fi

set -x

#for cpu in $(seq $CPUS $NCPUS); do
#  echo 0 | sudo tee /sys/devices/system/cpu/cpu$cpu/online &> /dev/null
#done

# Main program
sudo ./XDP/xdp_collect.py -i $IF -t $TIME -a $AGG

#for cpu in $(seq 1 $NCPUS); do
#  echo 1 | sudo tee /sys/devices/system/cpu/cpu$cpu/online &> /dev/null
#done

set +x

cat ./flows.csv

echo "Finished! Exported data to ./flows.csv"
