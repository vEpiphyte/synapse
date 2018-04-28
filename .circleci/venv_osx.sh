#!/usr/bin/env bash
source ~/.bash_profile
which pyenv
ls -ltha ~/
if [ ! -d ~/.pyenv ]; then
  echo "No ~/.pyenv found"
  exit 1
else
  echo "Checking pyenv versions"
  ret=`pyenv versions | grep syn36`
  echo $ret
  if [ $? -eq 0 ]; then
    echo "syn36 venv found"
    exit 0
  fi
fi

echo "Adding syn36 venv and installing packages"
pyenv virtualenv --copies 3.6.5 syn36
pyenv shell syn36
python3 -m pip install -U wheel pip pytest pytest-cov pycodestyle codecov