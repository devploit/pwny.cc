---
description: >-
  This is an attack in which an attacker perturbs an input such that a model
  produces an incorrect output (for example: this photo of a dog is now
  classified as a corkscrew)
---

# Evasion

Here's a helpful guide where we define some attacks based on the amount of access required (how much data do you have about model internals) and whether the attack is targeted (are you trying to force the classification to a specific class):

<table><thead><tr><th>Attack</th><th width="347">Access</th><th>Targeted</th></tr></thead><tbody><tr><td>Random</td><td>Any</td><td>No</td></tr><tr><td>Carlini L2</td><td>Gradients (Open box attack)</td><td>Both</td></tr><tr><td>SimBA</td><td>Probabilities (Partial knowledge attack)</td><td>Both</td></tr><tr><td>HopSkipJump</td><td>Single label (Closed box attack)</td><td>No (bc time)</td></tr></tbody></table>

When you're attacking models, access typically comes in one of three flavors:

* **Gradient Access** (or "Open box" attack): You have complete access to the model, either by stealing it, or by the victim using a pretrained model that you have identified and found your own copy of on say, HuggingFace. In this case, you can use open-box gradient-based attacks. These attacks use the weights (parameters of the model).
* **Scores** (or "gray-box" attack): You have API access to the model which provides complete numerical outputs of the model. In this case, you can use methods that estimate the gradients from the scores, `{"class_0: "0.89, class_1: 0.06, class_2: 0.049, class_3: 0.01}`. These attacks use "soft" labels, or probabilities from the output.
* **Labels** (or "closed-box" attack): You have API access to the model that only returns the label of the input (or, occasionally, the top 5 or so labels). In this case, you are often forced to use noisier techniques that estimate gradients based on sampling. `[class_0, class_1, class_2, class_3]`. These are "hard" labels, and represent the represent the most difficult targets, with `[class_0, class_1]` theoretically being the most difficult. Some algorithms (like HopSkipJump) can use any access.

Usually attacks are targeted or untargeted:

* **Targeted Attack**: In a targeted attack, the goal is to modify the image so that the model classifies the perturbed image as a specific, chosen target class. The attack carefully adjusts the perturbation to change the model’s prediction from the original class to the desired target class. This requires more precision, as it directs the perturbation toward a particular classification.
* **Untargeted Attack**: In an untargeted attack, the goal is simply to cause the model to misclassify the image, without needing it to fall into any specific target class. The attack modifies the image until the model predicts any class different from the original one. This is generally easier to achieve since it doesn’t require a specific outcome, just a change in classification.

## Attacks

### Random Attack

* A **Random Attack** is a simple, baseline approach where random noise or perturbations are added to an input to see if it will mislead the model. This type of attack does not rely on any information about the model’s internals or predictions, making it a "blind" or brute-force approach.
* Since it doesn’t leverage any model feedback, it is often ineffective compared to more sophisticated methods. However, it can sometimes succeed against poorly robust models.
* [exercise-1.md](exercise-1.md "mention")

### Carlini L2 Attack

* The **Carlini L2 Attack** is a gradient-based attack designed by Nicholas Carlini and David Wagner, specifically crafted to create small, imperceptible changes in input images to fool a neural network classifier.
* It minimizes the **L2 distance** (the Euclidean distance) between the original input and the adversarial input, making the modifications less noticeable. This attack requires access to the model’s gradients, which allows it to carefully calculate how to modify each pixel to achieve a specific misclassification.
* It is one of the most powerful attacks against machine learning models, especially deep neural networks, as it often succeeds while keeping the perturbations minimal and visually undetectable.
* [https://arxiv.org/abs/1608.04644](https://arxiv.org/abs/1608.04644)
* [exercise-2.md](exercise-2.md "mention")
* [exercise-3.md](exercise-3.md "mention")

### SimBA (Simple Black-box Adversarial Attack)

* The **SimBA** attack is a **black-box** attack that requires only the output probabilities of the model, not the gradients. It works by perturbing pixels or groups of pixels one at a time and observing how these changes impact the model’s prediction probability.
* SimBA iteratively applies perturbations and uses the model’s probability scores to decide which changes push the model toward misclassification with minimal modification.
* Because it doesn’t require gradient access, it is suitable for attacking models when only limited information is available (e.g., only probability outputs are accessible).
* [https://arxiv.org/abs/1608.04644](https://arxiv.org/abs/1608.04644)
* [exercise-4.md](exercise-4.md "mention")

### HopSkipJump Attack

* **HopSkipJump** is another **black-box** attack that only requires the final predicted label, not the full probability distribution or gradients. It is based on the principle of **boundary attacks**, where the adversarial example is gradually moved towards the decision boundary between classes until it crosses over into the target misclassified category.
* This attack works by exploring the decision boundary through iterative steps, “hopping” toward the boundary and adjusting direction based on feedback from the predicted class label.
* HopSkipJump is efficient in closed-box scenarios, but creating a targeted version (to achieve a specific misclassification) can be time-consuming because it needs a series of small adjustments to gradually push the input to the desired target class.
* [https://arxiv.org/abs/1904.02144](https://arxiv.org/abs/1904.02144)

{% embed url="https://arxiv.org/abs/1608.04644" %}
