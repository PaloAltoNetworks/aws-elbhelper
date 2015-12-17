# each FW mgmgt IP corresponds to exactly one zone
FIREWALLS={
    '52.34.238.152': 'us-west-2b',
    '52.33.165.26': 'us-west-2a'
}
FW_PWD='paloalto'

# make sure addr octet ends with a dot
AZ_PREFIX_MAP={
    'us-west-2a': '10.0.1.',
    'us-west-2b': '10.0.10.'
}

# internal ELB that NAT rule will point to
ELB_DNS='All.internal-InternalWebFarm-1015733533.us-west-2.elb.amazonaws.com'

# S3 Bucket where the database is stored at
S3_BUCKET='pantemplates'
S3_CREDENTIALS_PROFILE='aws'
S3_HA=True

# how often should we check for changes (in seconds)
SLEEP=10

# where is our ansible library stored at?
#ANSIBLE_LIBRARY='/Users/ibojer/SourceCode/ansible-pan/library'
ANSIBLE_LIBRARY='/home/ubuntu/ansible-pan/library'

# DO NOT CHANGE ANYTHING BELLOW
DB_FILE='files/db.txt'
PLAYBOOK='files/simple_playbook.yml'
VERBOSE=True
DEBUG=False

