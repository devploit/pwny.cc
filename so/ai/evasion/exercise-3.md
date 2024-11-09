---
description: Carlini L2 Attack
---

# Exercise 3

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

Okay. Here's the deal. These attacks are cool, but there are some very real operational constraints, primarily as it relates to lossy data conversions. Let's explore one of those now.

1. Save the adversarial image (`masked_pil`) as a `jpeg` (`masked_pil.save()`)
2. Reload it from disk, process it, and submit it to the model and examine the output
3. Repeat steps 2 and 3 but save your adversarial image as a `png`
4. Can you explain what's going on?

Success criteria:

* Just complete the steps: most of the time, the jpg image should no longer be an effective evasion, while the png might still work (if they both work, then you got luck or unlucky depending on your point of view... try creating a new adversarial image?)

What we want you to get out of this:

* The results we get from evasions may not correspond to real-world images that can be saved to and loaded from a file -- you might have to do a bit more work to get something you can submit to a model API.
  * Hint: look at the individual pixel values in your mask, and compare to the pixel values you get from the image version after you load it
* Lossy vs lossless image formats can (often) have an impact
* Start thinking about defenses: if saving it to a file and loading it can (sometimes) screw up the evasion, what else might defend against these evasions?

## Solution

The goal here is to understand the ways in which the compression of images can impact our attack approaches. Here we save and retrieve the adversarial image both as a JPG and PNG format and observe the changes in the prediction.

{% code overflow="wrap" %}
```python
# save the masked img as a jpg
masked_img_tensor = img_tensor + mask_parameter
masked_pil = tensor_to_pil(masked_img_tensor)
masked_pil.save(fp='output.jpg')

# load the same img
new_img = Image.open("output.jpg")

# just evaluating, no need for gradients
with torch.no_grad():
    # preprocess, move to the right device
    jpg_img_array = preprocess(new_img).to(device).unsqueeze(0)
    # submit to the model for inference
    outputs = model(jpg_img_array)[0].argmax()

print("Target index is:", outputs)
print("Target label is:", labels[outputs])

# repeat for PNG
masked_pil.save(fp='output.png')

new_img = Image.open("output.png")

with torch.no_grad():
    png_img_array = preprocess(new_img).to(device).unsqueeze(0)
    outputs = model(png_img_array)[0].argmax()

print("Target index is:", outputs)
print("Target label is:", labels[outputs])
```
{% endcode %}

* **Why did our prediction change?** JPEG uses **lossy** compression, which discards image data to reduce file size. This compression may impact the color channel data and pixel values themselves. Remember, our model isn't "seeing" the picture - it's processing a vectorized representation. Compression introduces changes to underlying values across the image, and therefore can impact inference.
* **What about PNG images?** PNG is a "lossless" format, so in theory it preserves the original image data. However, the prediction may have still changed. PNG compression implementations may sometimes lead to differences from the original image due to floating-point precision issues in the compression / decompression process.
* **What does all of this mean for defense against evasion attacks?** Discrepencies between the model inference of non-compressed and compressed images could help a system to detect possible adversarial examples.

If you want some real nightmare fuel, you can visualize the changes caused by the compression.

```python
# visualize the compression changes

jpg_pil = tensor_to_pil(img_tensor - jpg_img_array)
png_pil = tensor_to_pil(img_tensor - png_img_array)

plt.figure(figsize=(10, 5)) 
plt.subplot(1, 2, 1)
plt.imshow(jpg_pil)
plt.title(f"JPG Compression")
plt.axis('off')

plt.subplot(1, 2, 2)
plt.imshow(png_pil)
plt.title(f"PNG Compression")
plt.axis('off')

plt.show()
```
