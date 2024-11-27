{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.grpc
    pkgs.protobuf
    pkgs.cmake
    pkgs.gcc
  ];
}
