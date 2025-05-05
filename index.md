---
layout: default
title: Blog
---

<div class="centered-intro">
  <img src="/assets/images/avatar.png" alt="Avatar" class="avatar" />
  <h1>Hunting Things</h1>
  <p class="tagline">A  blog about Threat Hunting, DFIR & Blue Team things...</p>
</div>

<section class="post-list">
  <h2>> Recent Posts</h2>
  <ul>
    {% for post in site.posts limit: 10 %}
      <li>
        <span><a href="{{ post.url }}">{{ post.title }}</a></span>
        <small>{{ post.date | date: "%b %-d, %Y" }}</small>
      </li>
    {% endfor %}
  </ul>
  <p class="see-all"><a href="/archive.html">See all posts</a></p>
</section>