import http.client
import os
import hashlib
import json
import glob
import sys

xapikey = os.environ["XAPIKEY"]
version = os.environ["VERSION"]

def artifact_files(filename):
  files = [x for x in glob.glob(os.environ["CIRCLE_ARTIFACTS"] + '/**/' + filename, recursive=True)]
  return sorted(files)

def sha256sum(filename):
  h = hashlib.sha256()
  b = bytearray(128 * 1024)
  mv = memoryview(b)
  with open(filename, "rb", buffering=0) as f:
    for n in iter(lambda: f.readinto(mv), 0):
      h.update(mv[:n])
  return h.hexdigest()

conn = http.client.HTTPSConnection("6yq56qvgu2.execute-api.us-east-1.amazonaws.com")

artifacts = []

for file in artifact_files('*.deb'):
    item = {
        "path": file,
        "sha256": sha256sum(file)
    }
    artifacts.append(item)

post_data = {
 "source": "circleci",
 "github_project": "xv_helium_tun",
 "build_id": os.environ["CIRCLE_BUILD_NUM"],
 "artifact_version": version,
 "commit_hash": os.environ["CIRCLE_SHA1"],
 "build_type": "build",
 "artifact_list": artifacts
}

post_data["branch"] = os.environ["CIRCLE_BRANCH"]

if "BUILDTYPE" in os.environ:
    post_data["build_type"] = os.environ["BUILDTYPE"]
elif "CIRCLE_TAG" in os.environ:
    post_data["build_type"] = "tag"
    post_data["tag"] = os.environ["CIRCLE_TAG"]
    post_data["branch"] = ""  # For backwards compatibility
else:
    post_data["build_type"] = "branch"

headers = {
  "Content-Type": "application/json",
  "x-api-key": xapikey,
  "Host": "6yq56qvgu2.execute-api.us-east-1.amazonaws.com"
}

print("POSTING: " + json.dumps(post_data))

conn.request("POST", "/prod/v1/circle-ci-artifact", json.dumps(post_data), headers)

res = conn.getresponse()
data = res.read()

if res.status != 200:
 print("ERROR Posting to XV Artifact Store")
 sys.exit(1)

print("RESPONSE: " + data.decode("utf-8"))
