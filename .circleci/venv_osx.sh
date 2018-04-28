#!/usr/bin/env bash
source ~/.bash_profile
if [ -d ~/.pyenv ]; then
  pyenv versions | grep syn36
  if [ $? -eq 0 ]; then
    exit 0
  fi
else
  exit 1
fi

# Make a venv from 3.6.5 and install some base packages in it
pyenv virtualenv --copies 3.6.5 syn36
pyenv shell syn36
python3 -m pip install -U wheel pip pytest pytest-cov pycodestyle codecov