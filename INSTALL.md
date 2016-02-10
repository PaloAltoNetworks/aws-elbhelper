### Instalation

1.	instantiate ami-bca545dc (us-west-2 only) and ssh to it (ssh ubuntu@<SOME IP>)
2.	update config file so that it uses your env settings
    vim ~/aws-elbhelper/elbhelper/config/defaults.py
3.	update AWS credentials
    vim ~/.aws/credentials
4.	run it
    cd ~/aws-elbhelper/elbhelper
    python elbhelper.py
