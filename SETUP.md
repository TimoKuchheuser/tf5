# TF5 File Transfer | Initial Setup

If you have any questions or problems during the setup, please don't hesitate to contact us: [Julia Wiggeshoff](mailto:julia.wiggeshoff@uk-koeln.de), [Timo Kuchheuser](mailto:timo.kuchheuser@uk-koeln.de), and [Oliver Kutz](mailto:Oliver.Kutz@ukdd.de). If you find a bug or have suggestions for improvement, please fork our code on GitHub and send us a pull request.

## Prerequisites

In order to use the TF5 repository and create its custom environment, you need to have the following prerequisites installed on your system:

1. [Anaconda or miniconda](https://conda.io/projects/conda/en/latest/user-guide/install/index.html#regular-installation)
2. [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)
3. Python 3.11.4 and additional libraries
    - PyNaCl=1.5.0
    - black=23.7.0
    - libsodium=1.0.18

### Network and firewall

Your local computer must be able to access the following servers:

* github.com on port 443 (https)
* tf5.nngm.de on port 22 (ssh)

## Setup environment

1. Create a new directory, e.g. tf5
```
mkdir tf5
```
2. Change into the newly created directory
```
cd tf5
```
3. Clone repository
```
git clone https://github.com/nNGM-TF5/XXXX
```
4. Create an environment with conda or install dependencies with pip
- Option 1: Conda environment with [requirements_conda.txt](requirements_conda.txt)
```
conda activate

conda create --name tf5 --file requirements_conda.txt -c conda-forge -c bioconda -c default
```
- Alternative: If you have [mamba](https://github.com/mamba-org/mamba) installed as a package manager, which is an excellent replacement to conda, an alternative would be:
```
mamba create --name tf5 -c conda-forge -c bioconda -c default pynacl=1.5.0 black=23.7.0 libsodium=1.0.18
```
- Option 2: Install dependencies with pip and [requirements.txt](requirements.txt)
```
pip install -r requirements.txt
```
## Update environment
After the initial script usage during the onboarding process (see `USAGE.md``) and the subsequent administrator's update of the repository with new public keys, it's essential to regularly refresh the cloned repository. This ensures it consistently incorporates the latest public keys from participating centers within the nNGM project.
```
git pull
```
