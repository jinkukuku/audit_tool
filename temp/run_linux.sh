#!/bin/bash
# Python 3.10.18 압축 해제, 빌드, main.py 실행 스크립트 (전역 설치 X)

TGZ_FILE="./Python/Linux/Python-3.10.18.tgz"
DEST_DIR="./Python/Linux/"
PY_DIR_NAME="Python-3.10.18"
PY_SRC="$DEST_DIR/$PY_DIR_NAME"
PY_BIN="$PY_SRC/python"

# 압축 파일 확인
if [ ! -f "$TGZ_FILE" ]; then
    echo "압축 파일이 없습니다: $TGZ_FILE"
    exit 1
fi

# python 실행 파일이 이미 존재한다면 빌드 과정 생략
if [ -x "$PY_BIN" ]; then
    echo "이미 빌드된 Python이 존재합니다. (재빌드 생략)"
else
    # 압축 해제 여부 확인
    if [ ! -d "$PY_SRC" ]; then
        echo "압축을 풀고 있습니다..."
        tar -xvzf "$TGZ_FILE" -C "$DEST_DIR"
    else
        echo "이미 압축이 풀려 있습니다."
    fi

    # 빌드
    cd "$PY_SRC" || { echo "디렉토리 이동 실패: $PY_SRC"; exit 1; }

    echo "Python configure 실행 중..."
    ./configure --enable-optimizations

    echo "Python 빌드 중...(시간이 걸릴 수 있습니다)"
    make -j$(nproc)

    # 빌드 결과 확인
    if [ ! -x "./python" ]; then
        echo "빌드 실패: python 실행 파일이 없습니다."
        exit 1
    fi

    # 원래 경로로 복귀
    cd - >/dev/null
fi

# main.py 실행
echo "Python으로 main.py 실행 중..."
"$PY_BIN" ./main.py

