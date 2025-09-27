---
layout: default
title: Blog
---

<div class="hero">
  <div class="hero-content">

    <img src="/assets/images/avatar.png" alt="Avatar" class="avatar-large" />
    <h1>Blue Ronin</h1>
    <p class="tagline">A blog about Threat Hunting, DFIR & Blue Team things...</p>
  </div>
</div>

<section class="post-list">
  <h2>> Recent Posts</h2>
  <ul>
    {% for post in site.posts limit: 10 %}
      <li>
        <a href="{{ post.url }}">{{ post.title }}</a>
        <span class="post-date">{{ post.date | date: "%b %-d, %Y" }}</span>
      </li>
    {% endfor %}
  </ul>
  <p class="see-all"><a href="/archive.html">See all posts</a></p>
</section>
