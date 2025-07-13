import React, { type ReactNode } from 'react'
import classes from './Layout.module.scss'
export default function Layout({
    children
}:{
    children:ReactNode
}) {
  return (
    <div className={classes.root}>
        <header className={classes.container}>
          <a href="" className={classes.logo}>
            <img src="./logo.svg" alt="" />
          </a>
        </header>

        <main className={classes.container}>
            {children}
        </main>


        <footer className={classes.container}>
          <ul className={classes.footer}>
            <li>
              <img src="./logo-dark.svg" alt="" />
              <span> 2025</span>
            </li>
            <li><a href=""></a>Accessibility</li>
            <li><a href=""></a>User Agreement</li>
            <li><a href=""></a>Privacy Policy</li>
            <li><a href=""></a>Cookie Policy</li>
            <li><a href=""></a>Copywright Policy</li>
            <li><a href=""></a>Brand Policy</li>
            <li><a href=""></a>Guest Controler</li>
            <li><a href=""></a>Community Guidelines</li>
            <li><a href=""></a>Language</li>
          </ul>
        </footer>
    </div>
  )
}
