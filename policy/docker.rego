package main

import rego.v1

deny contains msg if {
  input[i].Cmd == "run"
  contains(lower(input[i].Value[0]), "curl")
  msg := "Curl is not allowed in Dockerfile"
}

deny contains msg if {
  input[i].Cmd == "run"
  contains(lower(input[i].Value[0]), "wget")
  msg := "Wget is not allowed in Dockerfile"
}