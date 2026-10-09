# Shell helpers for the Jenkinsfile's Deploy stage (sourced, not run).
# They update the image name and tag in a deployment repository and push the
# commit; Argo CD then applies it to the cluster.
#
# Expects in the environment: REGISTRY, TAG, DEPLOY_REPO, GIT_USER, GIT_PASS
# (GIT_PASS comes from a Jenkins credential and is never echoed), and
# GIT_COMMIT/JOB_NAME/BUILD_URL, which Jenkins sets.

clone_deploy_repo() {
    # git asks for the password through this helper, so the token is never
    # part of a URL or a command line that could end up in the log
    ASKPASS="$(mktemp)"
    printf '#!/bin/sh\necho "$GIT_PASS"\n' > "$ASKPASS"
    chmod 700 "$ASKPASS"
    export GIT_ASKPASS="$ASKPASS" GIT_TERMINAL_PROMPT=0
    rm -rf deploy
    git clone --quiet --depth 1 "https://${GIT_USER}@github.com/${DEPLOY_REPO}.git" deploy
    cd deploy
}

# set_image <image name> <kustomization file>
# Turns the image's entry in the kustomization's images: list into
#     - name: <image>
#       newName: <registry>/<image>
#       newTag: <tag>
# Safe to run again: an existing newName line is replaced, not duplicated.
set_image() {
    sed -i -e "/- name: $1 /,/newTag:/{/newName:/d;s|^    newTag:.*|    newName: ${REGISTRY}/$1                    # set by Jenkins: the registry it was pushed to\n    newTag: ${TAG}                               # set by Jenkins: the commit it was built from|}" "$2"
    grep -q "newName: ${REGISTRY}/$1 " "$2" || { echo "set_image: no images entry for $1 in $2" >&2; exit 1; }
}

# commit_and_push "<what changed>"
commit_and_push() {
    if git diff --quiet; then
        echo "Deployment repository already points at ${TAG}; nothing to commit."
        return 0
    fi
    git -c user.name="Jenkins CI" -c user.email="jenkins@k3s-srv.local" commit --quiet -am "ci(deploy): $1 -> ${TAG}

Built and pushed by Jenkins (${JOB_NAME} ${BUILD_URL:-}) from commit ${GIT_COMMIT}.
Image registry: ${REGISTRY}"
    # someone may have pushed in between: rebase and retry a few times
    for attempt in 1 2 3; do
        if git push --quiet origin HEAD:main; then
            echo "Pushed: $1 -> ${TAG}. Argo CD will deploy it."
            return 0
        fi
        git pull --quiet --rebase origin main
    done
    echo "Could not push to ${DEPLOY_REPO} after 3 attempts" >&2
    return 1
}
