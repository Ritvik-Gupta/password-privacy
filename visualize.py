import pandas as pd
import plotly.express as px

df = pd.read_csv("./visualizations/anonymities.csv")

fig1 = px.line(
    df,
    x="first_bits",
    y="k_anonymity_achieved",
    color="digest",
    markers=True,
    log_y=True,
    title="K Anonymity Achieved for Digests",
)
fig1.show()

fig2 = px.line(
    df,
    x="first_bits",
    y="anonymity_imapct",
    color="digest",
    markers=True,
    log_y=True,
    title="Anonymity Heuristic Impact for Digests",
)
fig2.show()
