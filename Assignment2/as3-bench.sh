# set -x

# This is the benchmark script to run for assignment2 of CS7NS1/CS4400

JOHNBIN=~/code/JohnTheRipper/run/john
CURL=`which curl`
CURLPARMS="-s"
OUTPUT="ass3.broken"
# VALIDATOR="as2-validator.sh"
FORMAT="md5crypt"
WORDLIST=~/Desktop/ScalableComputing/Assignment2/rockyou.txt
LOCAL="no"

# timestamps are handy
function whenisitagain()
{
    date -u +%Y%m%d-%H%M%S
}
NOW=$(whenisitagain)

if [ ! -f $JOHNBIN ]
then
	echo "Compile john first."
	exit 99
fi

if [[ "$CURL" == "" ]]
then
	echo "Install curl first."
	exit 98
fi	

#if [ ! -f $VALIDATOR ]
#then
#	echo "Can't find validator $VALIDATOR - better fix that"
#	exit 97
#fi


# usage
function usage()
{
	echo "usage: $0 [-f format] [-l]" 
	exit 99
}

# options may be followed by one colon to indicate they have a required argument
if ! options=$(getopt -s bash -o f:lh -l format:,local,help -- "$@")
then
	# something went wrong, getopt will put out an error message for us
	exit 1
fi
eval set -- "$options"
while [ $# -gt 0 ]
do
	case "$1" in
		-h|--help) usage;;
		-f|--format) FORMAT=$2; shift;;
		-l|--local) LOCAL="yes";;
		(--) shift; break;;
		(-*) echo "$0: error - unrecognized option $1" 1>&2; exit 1;;
		(*)  break;;
	esac
	shift
done

tmpf=`mktemp /tmp/as3-XXXX`

# use aws metadata to get info about instance/AMI
if [[ "$LOCAL" != "yes" ]]
then
	echo "AWS Meta-data:" >>$tmpf
	$CURL $CURLPARMS http://169.254.169.254/latest/meta-data >>$tmpf 2>&1 
	echo "" >>$tmpf
	$CURL $CURLPARMS http://169.254.169.254/latest/meta-data/instance-type >>$tmpf 2>&1
	echo "" >>$tmpf
	$CURL $CURLPARMS http://169.254.169.254/latest/meta-data/instance-id >>$tmpf 2>&1
	echo "" >>$tmpf
	$CURL $CURLPARMS http://169.254.169.254/latest/meta-data/ami-id >>$tmpf 2>&1
	echo "" >>$tmpf
	$CURL $CURLPARMS http://169.254.169.254/latest/meta-data/hostname >>$tmpf 2>&1
	echo "" >>$tmpf
	echo "" >>$tmpf
fi

# run john 
echo "John bench mark:" >>$tmpf
echo "" >>$tmpf
$JOHNBIN --format=$FORMAT --wordlist=$WORDLIST millana.hashes >>$tmpf

# keep a backup version of previous output
if [ -f $OUTPUT ]
then
	echo "backing up $OUTPUT to $OUTPUT.$NOW just in case you want that later."
	mv $OUTPUT $OUTPUT.$NOW
fi

mv $tmpf $OUTPUT

# validate output
#result=`./$VALIDATOR $OUTPUT`
#if [[ "$result" == "ok" ]]
#then
#	echo "$OUTPUT looks good to submit"
#else
#	echo "$OUTPUT looks doddy - check what $VALIDATOR didn't like"
#fi

echo "Your output is in $OUTPUT"




