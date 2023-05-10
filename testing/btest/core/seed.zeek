# @TEST-DOC: Test specifying seeds via ZEEK_SEED_VALUES
# @TEST-EXEC: echo "test seed" >> output
# @TEST-EXEC: zeek -b %INPUT >> output
# @TEST-EXEC: bash -c 'ZEEK_SEED_VALUES=$(paste -d " " $ZEEK_SEED_FILE) ZEEK_SEED_FILE= zeek -b %INPUT' >> output
# @TEST-EXEC: echo "1 to 21" >> output
# @TEST-EXEC: bash -c 'ZEEK_SEED_FILE= ZEEK_SEED_VALUES=$(echo {1..21}) zeek -b %INPUT ' >> output
# @TEST-EXEC: ZEEK_SEED_FILE= ZEEK_SEED_VALUES="1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21" zeek -b %INPUT >> output
# @TEST-EXEC: echo "21 x 0, deterministic" >> output
# @TEST-EXEC: ZEEK_SEED_FILE= ZEEK_SEED_VALUES="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0" zeek -b %INPUT >> output
# @TEST-EXEC: ZEEK_SEED_FILE= zeek -D -b %INPUT >> output
# @TEST-EXEC: echo "different" >> output
# @TEST-EXEC: ZEEK_SEED_FILE= ZEEK_SEED_VALUES="10 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1" zeek -b %INPUT >> output
# @TEST-EXEC: ZEEK_SEED_FILE= ZEEK_SEED_VALUES="20 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2" zeek -b %INPUT >> output
# @TEST-EXEC: ZEEK_SEED_FILE= ZEEK_SEED_VALUES="30 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3 3" zeek -b %INPUT >> output
# @TEST-EXEC: echo "writing seeds (twice)" >> output
# @TEST-EXEC: ZEEK_SEED_FILE= ZEEK_SEED_VALUES="0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21" zeek -b %INPUT -H seeds.out >> output
# @TEST-EXEC: ZEEK_SEED_FILE= ZEEK_SEED_VALUES="0 1 2 3 4 5 6 7 8 9 10 9 8 7 6 5 4 3 2 1 0" zeek -b %INPUT -H seeds.out >> output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff seeds.out

print rand(500000), unique_id("C");
