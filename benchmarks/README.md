# Benchmarks

Both benchmarks run memem's real code locally, inside the benchmark, with the same embedding model as the Worker.
Neither touches a live deployment. They run on GitHub Actions from this branch, and only when asked.

| Benchmark | What it measures | Cost | Time |
| --- | --- | --- | --- |
| [LongMemEval](longmemeval.py) | Retrieval only: can search find the conversation that holds the answer? Whole conversations are saved, so it says nothing about what an assistant would save. | Free | About 2.5 hours on 10 machines |
| [LoCoMo](locomo.py) | End to end: Claude Haiku 5.5 saves memories with memem's tools, then answers questions using only memem's search, graded by a Haiku judge. Compares the current tools with `BASELINE_REF`, main before the accuracy work. | About $3.60 of Anthropic API usage | About 20 minutes on 20 machines |

## Set up LoCoMo once

LoCoMo needs an Anthropic API key, stored as a repository secret. Add it yourself; the command asks for the key:

```bash
gh secret set ANTHROPIC_API_KEY --repo rushtehrani/memem
```

Charges go to that key's account. Secrets are not passed to workflows triggered from forks.

## Run

Pushing to this branch runs nothing by itself. Push a commit whose message names the benchmark:

```bash
git commit --allow-empty -m "Run LoCoMo [run locomo]" && git push
```

```bash
git commit --allow-empty -m "Run LongMemEval [run longmemeval]" && git push
```

## Results

Each run uploads its results as artifacts: `longmemeval-results`, or `locomo-comparison` plus one file per
conversation and version with every saved memory and answer. The merge job also prints the summary table in its log.

```bash
gh run download <run id> --repo rushtehrani/memem --name locomo-comparison
```

## Running one locally

Useful for checking a change on one conversation. LoCoMo needs `ANTHROPIC_API_KEY` in the environment.

```bash
uv run --no-project --python 3.12 --with anthropic --with fastembed --with numpy python benchmarks/locomo.py --conversations 0
```

## Limits

- LoCoMo results vary between runs, because the model decides what to save. Compare versions over all 10
  conversations, not one.
- Haiku stands in for the assistant in real chats, which is usually a larger model.
- Neither score is comparable with other products' published numbers, which use different models and setups.
