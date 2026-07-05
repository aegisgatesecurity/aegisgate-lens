=== AegisGate Lens v0.1.0-beta -- Prompt Injection Training ===
Device: cuda
Base model: answerdotai/ModernBERT-base
Output: /home/chaos/Desktop/AegisGate/aegisgate-lens/models/prompt-injection-v0.1.0-beta
Train: /home/chaos/Desktop/AegisGate/aegisgate-lens/corpora/v01beta-raw/v01beta-train.jsonl
Val: /home/chaos/Desktop/AegisGate/aegisgate-lens/corpora/v01beta-raw/v01beta-val.jsonl

Loading tokenizer...
Loading model...
Some weights of ModernBertForSequenceClassification were not initialized from the model checkpoint at answerdotai/ModernBERT-base and are newly initialized: ['classifier.bias', 'classifier.weight']
You should probably TRAIN this model on a down-stream task to be able to use it for predictions and inference.
Loading data...
  Train: 10000 records
  Val:   1000 records

Training for 3 epochs (total steps: 1875 )...
  Epoch 1 Step 100 / 2500 Loss: 0.8086
  Epoch 1 Step 200 / 2500 Loss: 0.7227
  Epoch 1 Step 300 / 2500 Loss: 0.6953
  Epoch 1 Step 400 / 2500 Loss: 0.6016
  Epoch 1 Step 500 / 2500 Loss: 0.9414
  Epoch 1 Step 600 / 2500 Loss: 0.7695
  Epoch 1 Step 700 / 2500 Loss: 0.5938
  Epoch 1 Step 800 / 2500 Loss: 0.4824
Token indices sequence length is longer than the specified maximum sequence length for this model (31884 > 8192). Running this sequence through the model will result in indexing errors
  Epoch 1 Step 900 / 2500 Loss: 0.7969
  Epoch 1 Step 1000 / 2500 Loss: 0.8516
  Epoch 1 Step 1100 / 2500 Loss: 0.5117
  Epoch 1 Step 1200 / 2500 Loss: 0.6602
  Epoch 1 Step 1300 / 2500 Loss: 0.5469
  Epoch 1 Step 1400 / 2500 Loss: 0.5898
  Epoch 1 Step 1500 / 2500 Loss: 0.5859
  Epoch 1 Step 1600 / 2500 Loss: 0.4414
  Epoch 1 Step 1700 / 2500 Loss: 0.3691
  Epoch 1 Step 1800 / 2500 Loss: 0.4258
  Epoch 1 Step 1900 / 2500 Loss: 0.7617
  Epoch 1 Step 2000 / 2500 Loss: 0.3184
  Epoch 1 Step 2100 / 2500 Loss: 0.6484
  Epoch 1 Step 2200 / 2500 Loss: 0.5078
  Epoch 1 Step 2300 / 2500 Loss: 0.7305
  Epoch 1 Step 2400 / 2500 Loss: 0.6484
  Epoch 1 Step 2500 / 2500 Loss: 0.7383

  Epoch 1 complete. Avg loss: 0.6583
  Val TP= 500 FN= 0 FP= 486 TN= 14 | Recall= 1.0 FPR= 0.972 Precision= 0.5071 F1= 0.6729
  New best val recall: 1.0 . Saving model...
  Epoch 2 Step 100 / 2500 Loss: 0.8008
  Epoch 2 Step 200 / 2500 Loss: 0.7227
  Epoch 2 Step 300 / 2500 Loss: 0.1172
  Epoch 2 Step 400 / 2500 Loss: 0.4434
  Epoch 2 Step 500 / 2500 Loss: 0.4844
  Epoch 2 Step 600 / 2500 Loss: 0.5078
  Epoch 2 Step 700 / 2500 Loss: 0.3613
  Epoch 2 Step 800 / 2500 Loss: 0.4043
  Epoch 2 Step 900 / 2500 Loss: 0.4727
  Epoch 2 Step 1000 / 2500 Loss: 0.7422
  Epoch 2 Step 1100 / 2500 Loss: 0.7344
  Epoch 2 Step 1200 / 2500 Loss: 0.3477
  Epoch 2 Step 1300 / 2500 Loss: 0.6094
  Epoch 2 Step 1400 / 2500 Loss: 0.5469
  Epoch 2 Step 1500 / 2500 Loss: 0.4648
  Epoch 2 Step 1600 / 2500 Loss: 0.5117
  Epoch 2 Step 1700 / 2500 Loss: 1.6094
  Epoch 2 Step 1800 / 2500 Loss: 0.7148
  Epoch 2 Step 1900 / 2500 Loss: 0.3008
  Epoch 2 Step 2000 / 2500 Loss: 0.5586
  Epoch 2 Step 2100 / 2500 Loss: 0.5586
  Epoch 2 Step 2200 / 2500 Loss: 0.2227
  Epoch 2 Step 2300 / 2500 Loss: 0.7305
  Epoch 2 Step 2400 / 2500 Loss: 0.6641
  Epoch 2 Step 2500 / 2500 Loss: 0.5273

  Epoch 2 complete. Avg loss: 0.4984
  Val TP= 500 FN= 0 FP= 469 TN= 31 | Recall= 1.0 FPR= 0.938 Precision= 0.516 F1= 0.6807
  Epoch 3 Step 100 / 2500 Loss: 0.2812
  Epoch 3 Step 200 / 2500 Loss: 0.3789
  Epoch 3 Step 300 / 2500 Loss: 0.707
  Epoch 3 Step 400 / 2500 Loss: 0.8438
  Epoch 3 Step 500 / 2500 Loss: 0.6523
  Epoch 3 Step 600 / 2500 Loss: 0.5039
  Epoch 3 Step 700 / 2500 Loss: 0.5156
  Epoch 3 Step 800 / 2500 Loss: 0.7773
  Epoch 3 Step 900 / 2500 Loss: 0.5508
  Epoch 3 Step 1000 / 2500 Loss: 0.4629
  Epoch 3 Step 1100 / 2500 Loss: 0.4453
  Epoch 3 Step 1200 / 2500 Loss: 0.3047
  Epoch 3 Step 1300 / 2500 Loss: 0.582
  Epoch 3 Step 1400 / 2500 Loss: 0.5898
  Epoch 3 Step 1500 / 2500 Loss: 0.7461
  Epoch 3 Step 1600 / 2500 Loss: 0.5508
  Epoch 3 Step 1700 / 2500 Loss: 0.3711
  Epoch 3 Step 1800 / 2500 Loss: 0.3184
  Epoch 3 Step 1900 / 2500 Loss: 0.5781
  Epoch 3 Step 2000 / 2500 Loss: 0.6133
  Epoch 3 Step 2100 / 2500 Loss: 0.3516
  Epoch 3 Step 2200 / 2500 Loss: 0.8477
  Epoch 3 Step 2300 / 2500 Loss: 0.4824
  Epoch 3 Step 2400 / 2500 Loss: 0.2012
  Epoch 3 Step 2500 / 2500 Loss: 0.3848

  Epoch 3 complete. Avg loss: 0.4804
  Val TP= 500 FN= 0 FP= 466 TN= 34 | Recall= 1.0 FPR= 0.932 Precision= 0.5176 F1= 0.6821

=== Training complete. Best epoch: 1 (val recall 1.0 ) ===
Best model saved to: /home/chaos/Desktop/AegisGate/aegisgate-lens/models/prompt-injection-v0.1.0-beta /checkpoint-epoch 1

=== Held-out Evaluation (strict ship gate) ===
Targets: Recall >= 99%, FPR <= 1%, F1 >= 99%

Loading best checkpoint: checkpoint-epoch1
Held-out: 3210 records
  Attack: 2046 , Benign: 1164
Token indices sequence length is longer than the specified maximum sequence length for this model (9877 > 8192). Running this sequence through the model will result in indexing errors
Held-out TP= 1893 FN= 153 FP= 793 TN= 371 | Recall= 0.9252 FPR= 0.6813 Precision= 0.7048 F1= 0.8001

============================================================
  SHIP GATE FAILED.
    Recall 0.9252 < 0.99 ( 153 attacks missed)
    FPR 0.6813 > 0.01 ( 793 false positives)
    F1 0.8001 < 0.99
Need to retrain. Do NOT proceed to Phase 0c.
