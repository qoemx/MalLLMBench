# LLM method configurations (qwen38-27b, all reported runs)

| Parameter | Value |
|---|---|
| Model | qwen38-27b (local vLLM, 2xGPU, FP8) |
| Temperature | 0.0 (headline); 0.3/0.7 (M1 ablation only) |
| Thinking mode | disabled (enable_thinking=false) |
| Sampling | greedy at T=0 |
| max_tokens | PE2: as per original method; AV-Agent P1=1000-1500, P2=2000-3000 |
| Repetitions | 3 per temperature on the fixed 300-sample set (M1) |

Method prompts/runners are NOT redistributed (see NOTICE.md); obtain from the original authors:
- PE2Prompt: (original paper + official repo)
- AV-Agent: (original paper + official repo)
