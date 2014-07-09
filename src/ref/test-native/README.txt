Quick native testing
--------------------
gcc -o pf_test_native pf_test_native.c -lpcap
luajit -l pf_test_native -e 'pf_test_native.run()'
