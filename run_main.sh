#! /bin/bash

appName=auth_hub

pathFile=$(realpath $0)
pathDir=$(dirname $pathFile)

cd $pathDir


find2="\[\'auth_hub_main\@mykhailo-pc1\'\]"
insert2="\[\'auth_hub_cluster1\@mykhailo-pc1\'\]"
perl -pi -e 's/'$find2'/'$insert2'/g' config/sys.config

find3="auth_hub_cluster1"
insert3="auth_hub_main"
perl -pi -e 's/'$find3'/'$insert3'/g' config/vm.args


rebar3 as prod release
cd ./_build/prod/rel/$appName/bin/
./$appName console
