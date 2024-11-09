---
description: '"Evasion" with random noise'
---

# Exercise 1

## Model

{% code overflow="wrap" %}
```python
import torch
from PIL import Image
from IPython import display

import pandas as pd
import torchvision
from torchvision import transforms

import numpy as np
import matplotlib.pyplot as plt

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(device)

#load the model from the pytorch hub
model = torch.hub.load('pytorch/vision:v0.10.0', 'mobilenet_v2', weights='MobileNet_V2_Weights.DEFAULT', verbose=False)

# Put model in evaluation mode
model.eval()

# put the model on a GPU if available, otherwise CPU
model.to(device);

# Define the transforms for preprocessing
preprocess = transforms.Compose([
    transforms.Resize(256),  # Resize the image to 256x256
    transforms.CenterCrop(224),  # Crop the image to 224x224 about the center
    transforms.ToTensor(),  # Convert the image to a PyTorch tensor
    transforms.Normalize(
        mean=[0.485, 0.456, 0.406],  # Normalize the image with the ImageNet dataset mean values
        std=[0.229, 0.224, 0.225]  # Normalize the image with the ImageNet dataset standard deviation values
    )
]);

def tensor_to_pil(img_tensor):
    # tensor: pre-processed tensor object resulting from preprocess(img).unsqueeze(0)
    unnormed_tensor = unnormalize(img_tensor)
    return transforms.functional.to_pil_image(unnormed_tensor[0])

unnormalize = transforms.Normalize(
   mean= [-m/s for m, s in zip([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])],
   std= [1/s for s in [0.229, 0.224, 0.225]]
)

# load labels
with open("../data/labels.txt", 'r') as f:
    labels = [label.strip() for label in f.readlines()]

# load an example image
img = Image.open("../data/dog.jpg")

plt.imshow(img)
plt.axis('off')
plt.show()

# preprocess the image
img_tensor = preprocess(img).unsqueeze(0)

print(f"Inputs information:\n---------------\nshape:{img_tensor.shape}\n")

# move sample to the right device
img_tensor = img_tensor.to(device)

with torch.no_grad():
    output = model(img_tensor)

print(f"Image tensor on device:\n---------------\n{img_tensor.device}\n")
print(f"Inputs information:\n---------------\nshape:{img_tensor.shape}\nclass: {type(img_tensor)}\n")
print(f"Shape of outputs:\n---------------\n{output.shape}\n")
print(f"Pred Index:\n---------------\n{output[0].argmax()}\n")
print(f"Pred Label:\n---------------\n{labels[output[0].argmax()]}\n")

unnormed_img_tensor= unnormalize(img_tensor)

img_pil = transforms.functional.to_pil_image(unnormed_img_tensor[0])
img_pil.show()
```
{% endcode %}

## Exercise

For fun, let's try to get a German Shepard randomly. Write a loop that,

1. Generates a random tensor and send it to the model for inference -- try modifying the rescaling of the random noise below (the `*1`, and `+0` bits)
2. Store the output index, output label, and image in a tuple
3. Add that tuple to a list
4. Stop when you get output index of `235` **OR have run `1000` queries**
5. Look at a few of the images

```python
queries = 1000
target_output = 235
tensor = torch.randn(3, 224, 224) * 1.0 + 0.0
```

Success criteria for this exercise **do not** require you to actually create a sample of random noise that gets classified as a German Shepherd: that's extremely unlikely (but let us know if it happens!) -- just to try to do it. Please stop at 1000 attempts.

What we expect you to get from this exercise:

1. Even though the images you have generated at random look like noise, the model still classifies them confidently (why?).
2. Random search is not an efficient way of generating adversarial samples.

## Solution

```python
queries = 1000
target_output = 235
output_index = 1000
i = 0

max_val = torch.max(img_tensor)
min_val = torch.min(img_tensor)
modifier = max_val-min_val
while not output_index == target_output:
    tensor = torch.randn(3, 224, 224).to(device) * modifier + min_val
    tensor = tensor.unsqueeze(0).to(device)
    output = model(tensor)
    output_index = output[0].argmax()
    output_label = labels[output_index]
    i+=1
    if i%100==1:
        print(output_index,output_label)
    if i == queries:
        break
print(output_index,output_label)
```

1. **Initial Parameters**:
   * `queries = 1000`: Sets a limit of 1000 queries to the model.
   * `target_output = 235`: The target output index the model is expected to predict.
   * `output_index = 1000`: Initializes the output index, which will update with each iteration.
   * `i = 0`: Counter to track the number of attempts.
2. **Tensor Value Range**:
   * `max_val` and `min_val`: Calculate the maximum and minimum values of the image tensor (`img_tensor`).
   * `modifier`: Sets the range of values for the tensor (`max_val - min_val`) to scale the random images generated.
3. **Main Loop**:
   * The `while` loop generates random tensors (`tensor = torch.randn(3, 224, 224)`) that are scaled and shifted to match the range of `img_tensor`.
   * The tensor is resized and passed to `model(tensor)` for prediction.
   * `output_index = output[0].argmax()`: Gets the index of the highest-probability class from the model’s output.
   * `output_label = labels[output_index]`: Maps the output index to a corresponding label.
   * Every 100 attempts, the code prints the current `output_index` and `output_label`.
4. **Termination**:
   * The loop stops if `output_index` matches `target_output` or if the maximum of 1000 iterations is reached.
   * Finally, the last `output_index` and `output_label` are printed.

**Purpose**: The code is randomly generating images to attempt to find one that the model classifies as a specific target class (`target_output`). This is a common approach in adversarial attacks or model testing where an image is generated to trigger a specific prediction.
